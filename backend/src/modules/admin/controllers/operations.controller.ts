import { FastifyInstance } from 'fastify';
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';
import { problem } from '../../../shared/models/problem';
import { appendLog, logBufferLength, readLogs, writeCount } from '../../../shared/services/logBuffer';
import { beginSSE, SSE_HEARTBEAT_FRAME, SSE_HEARTBEAT_MS } from '../../../shared/services/sse';
import {
  requireAdmin, adminCredential, issueAdminToken, sha256Hex,
} from '../../../vendors/middleware/adminAuth';
import { reloadDbRuntime } from '../../../plugins/mongodb';
import {
  ALLOWED_COMMANDS, BACKEND_ROOT, PROJECT_ROOT, frontendPort, killProcessOnPort,
  runAllowedCommand, runSequenceStep, spawnFrontend, streamProcess,
} from '../services/commandRunner';
import {
  aggregateSummaries, resolveTestSequence, resolveTestStrategy, TestSummary,
} from '../services/testRunners';
import { config } from '../../../config';

/**
 * The operations surface the console drives: sign in, run maintenance, watch the logs, read the
 * runtime, put the runtime back together.
 *
 * Everything here is behind the operator credential and none of it is part of the integration
 * contract. Two properties are load bearing and easy to lose in a refactor:
 *
 * - Only NAMED scripts run. The allowlist lives in the runner, and the shell route that has no
 *   allowlist is separately switchable and separately reported in the posture.
 * - Every stream heartbeats. A silent stream is dropped by an ingress and the console then waits
 *   forever on a run that already finished.
 */

const ENV_KEY = /^[A-Z_][A-Z0-9_]*$/i;

// Anything whose NAME suggests it carries a secret is masked before the runtime is published, even to
// an operator: a screenshot of this page travels further than the page does.
const SENSITIVE_KEY = [
  /secret/i, /password/i, /passwd/i, /key/i, /token/i, /uri/i, /url/i,
  /dsn/i, /credential/i, /aws_/i, /mongo/i,
];

// Names that match the patterns above and carry nothing secret. Masking these hides the very values an
// operator opened the page to check.
const PLAIN_KEYS = new Set([
  'GIAM_DB_NAME',
  'GIAM_DB_KEYVAULT',
  'GIAM_CRYPT_SHARED_LIB_PATH',
  'MONGODB_CRYPT_SHARED_LIB_PATH',
  'GIAM_KEY_PROVIDER',
  'GIAM_KMS_PROVIDER',
  'GIAM_BASE_URL',
  'GIAM_PUBLIC_URL',
  'GIAM_FRONTEND_URL',
  'GIAM_CORS_ORIGIN',
]);

function isSensitive(key: string): boolean {
  return !PLAIN_KEYS.has(key) && SENSITIVE_KEY.some((pattern) => pattern.test(key));
}

/** A connection string keeps everything but its password: the host is what an operator is checking. */
function maskConnectionString(value: string): string {
  return value.replace(/^(mongodb(?:\+srv)?:\/\/[^:/?#]*:)([^@]*)(@)/, '$1***$3');
}

function isConnectionString(key: string, value: string): boolean {
  return /uri/i.test(key) && (value.startsWith('mongodb://') || value.startsWith('mongodb+srv://'));
}

/**
 * The environment file the process actually reads, not a guess at where one should be.
 *
 * The service loads the first of several candidates, so writing to a different one would report a
 * change that took effect until the next restart and then silently reverted.
 */
function resolveEnvPath(): string {
  const candidates = [path.join(PROJECT_ROOT, '.env'), path.join(BACKEND_ROOT, '.env')];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? candidates[0];
}

const ENV_PATH = resolveEnvPath();

function readEnvKeys(): string[] {
  try {
    const keys: string[] = [];
    for (const line of fs.readFileSync(ENV_PATH, 'utf-8').split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || /^[#;]/.test(trimmed)) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      if (ENV_KEY.test(key)) keys.push(key);
    }
    return keys;
  } catch {
    return [];
  }
}

/** Writes one key, preserving comments, blank lines and the file's own line endings. */
function writeEnvKey(key: string, value: string): void {
  let content = '';
  try { content = fs.readFileSync(ENV_PATH, 'utf-8'); } catch { /* the file is created below */ }

  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const needsQuotes = /[ \t"'#\\=]/.test(value) || value === '';
  const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  const line = `${key}=${needsQuotes ? `"${escaped}"` : value}`;

  let found = false;
  const updated = content.split(/\r?\n/).map((existing) => {
    if (!existing.trim() || /^\s*[#;]/.test(existing)) return existing;
    const eq = existing.indexOf('=');
    if (eq !== -1 && existing.slice(0, eq).trim() === key) {
      found = true;
      return line;
    }
    return existing;
  });

  if (!found) {
    while (updated.length && !updated[updated.length - 1].trim()) updated.pop();
    updated.push(line, '');
  }

  fs.writeFileSync(ENV_PATH, updated.join(eol), 'utf-8');
}

/** A small in-memory limiter. Enough to make a password guess expensive without a shared store. */
function rateLimiter(maxRequests: number, windowMs: number) {
  const seen = new Map<string, { count: number; reset: number }>();
  return (ip: string): { allowed: boolean; retryAfter: number } => {
    const now = Date.now();
    const entry = seen.get(ip);
    if (!entry || entry.reset < now) {
      seen.set(ip, { count: 1, reset: now + windowMs });
      return { allowed: true, retryAfter: 0 };
    }
    if (entry.count >= maxRequests) {
      return { allowed: false, retryAfter: Math.ceil((entry.reset - now) / 1000) };
    }
    entry.count += 1;
    return { allowed: true, retryAfter: 0 };
  };
}

const limitSignIn = rateLimiter(10, 15 * 60 * 1000);
const limitOperations = rateLimiter(300, 15 * 60 * 1000);

const NO_STANDARD = 'No applicable standard.';
const STREAM_EXAMPLE = 'event: log\ndata: {"text":"setup complete"}\n\n';

/** The stream shape, declared once. Hijacked, so nothing here is ever used to serialise a body. */
const eventStreamResponse = (description: string) => ({
  description,
  content: {
    'text/event-stream': {
      schema: { type: 'string', examples: [STREAM_EXAMPLE] },
    },
  },
});

export async function operationsController(fastify: FastifyInstance) {

  fastify.post('/login', {
    schema: {
      operationId: 'createAdminSession',
      tags: ['admin'],
      summary: 'Sign in to the operations console',
      description:
        `${NO_STANDARD} Exchanges the operator name and password for a token valid for four hours. `
        + 'The password is never stored: the server compares its digest against the configured one. '
        + 'Public by nature, because it is where a credential is presented and so cannot require one '
        + 'first. Attempts are rate limited per address, which is the only thing standing between a '
        + 'guessable password and the whole operations surface.',
      security: [],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['username', 'password'],
        properties: {
          username: { type: 'string', examples: ['admin'] },
          password: { type: 'string', description: 'Compared as a digest, never stored or logged.' },
        },
      },
      response: {
        200: {
          description: 'Signed in.',
          type: 'object',
          additionalProperties: false,
          required: ['token'],
          properties: {
            token: { type: 'string', description: 'Present as a bearer token on the other operations routes.' },
          },
          examples: [{ token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' }],
        },
        401: { $ref: 'Problem#', description: 'The name or the password did not match.' },
        429: { $ref: 'Problem#', description: 'Too many attempts from this address.' },
        503: { $ref: 'Problem#', description: 'No operator credential is configured, so nobody can sign in.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitSignIn(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    const credential = adminCredential();
    if (!credential) {
      return reply.status(503).send(problem(
        503,
        'Sign-in is not configured',
        'Set GIAM_ADM_USER and GIAM_ADM_PASS to allow an operator to sign in.',
      ));
    }

    const { username, password } = request.body as { username: string; password: string };
    if (username !== credential.user || sha256Hex(password) !== credential.passwordDigest) {
      // The address is recorded, the name is not: a mistyped password is very often a password.
      appendLog(`[${new Date().toISOString()}] WARN ADMIN sign-in refused from ${request.ip}`);
      return reply.status(401).send(problem(401, 'Unauthorized', 'Invalid operator credentials.'));
    }

    appendLog(`[${new Date().toISOString()}] ADMIN sign-in accepted for "${username}" from ${request.ip}`);
    return reply.send({ token: issueAdminToken(username) });
  });

  fastify.post('/run', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'runAdminCommand',
      tags: ['admin'],
      summary: 'Run one named maintenance script',
      description:
        `${NO_STANDARD} Runs one of a fixed set of maintenance scripts and streams its output as `
        + 'server-sent events. The set is named in the source, not read from a package file, so a new '
        + 'capability is a decision somebody made rather than a consequence of editing a script entry. '
        + 'The stream sends a comment frame every fifteen seconds, because a long silent step is '
        + 'otherwise dropped by a proxy and the console waits forever on a run that already ended.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['command'],
        properties: {
          command: { type: 'string', enum: Object.keys(ALLOWED_COMMANDS), examples: ['setup:check'] },
        },
      },
      response: {
        200: eventStreamResponse('The run, streamed. Frames are `start`, `log`, `error` and `done`.'),
        400: { $ref: 'Problem#', description: 'No such command.' },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    const { command } = request.body as { command: string };
    if (!ALLOWED_COMMANDS[command]) {
      return reply.status(400).send(problem(400, 'Bad Request', `Unknown command "${command}".`));
    }

    appendLog(`[${new Date().toISOString()}] ADMIN run "${command}" requested from ${request.ip}`);

    // A test run uses the runner's own report rather than its terminal output, so the console renders
    // a result it was told rather than one it inferred from prose.
    const strategy = resolveTestStrategy(command, PROJECT_ROOT);
    const sequence = resolveTestSequence(command, PROJECT_ROOT);
    const raw = beginSSE(reply, request);

    const prepareReport = (file: string) => {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      // A stale report from a previous run would be presented as this run's result.
      try { fs.rmSync(file, { force: true }); } catch { /* none to remove */ }
    };

    if (sequence) {
      const summaries: TestSummary[] = [];
      for (const step of sequence) {
        prepareReport(step.strategy.outputFile);
        await runSequenceStep(raw, step.script, step.strategy.args);
        try {
          summaries.push(step.strategy.parse(fs.readFileSync(step.strategy.outputFile, 'utf-8')));
        } catch {
          // The suite ended before writing a report. The exit code already recorded the failure.
        }
      }
      const combined = aggregateSummaries(summaries);
      if (summaries.length > 0) raw.write(`event: summary\ndata: ${JSON.stringify(combined)}\n\n`);
      raw.write(`event: done\ndata: ${JSON.stringify({ text: `Process exited with code ${combined.failed > 0 ? 1 : 0}` })}\n\n`);
      raw.end?.();
      return;
    }

    if (strategy) {
      prepareReport(strategy.outputFile);
      await runAllowedCommand(raw, command, strategy.args, () => {
        try {
          return strategy.parse(fs.readFileSync(strategy.outputFile, 'utf-8'));
        } catch {
          // The suite ended before writing a report; the exit code is the result.
          return null;
        }
      });
      return;
    }

    await runAllowedCommand(raw, command);
  });

  fastify.post('/exec', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'runAdminShellCommand',
      tags: ['admin'],
      summary: 'Run a shell command in the checkout',
      description:
        `${NO_STANDARD} Runs an arbitrary command and streams its output. This is the one route with `
        + 'no allowlist, so it is switchable on its own with GIAM_ADMIN_SHELL and the posture report '
        + 'states which way it is set: a capability this broad should never be something a reader has '
        + 'to infer. The working directory is confined to the checkout, so a run cannot wander into '
        + 'the rest of the host through a relative path.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['command'],
        properties: {
          command: { type: 'string', examples: ['git status --short'] },
          cwd: { type: 'string', description: 'Must resolve inside the checkout. Defaults to its root.' },
        },
      },
      response: {
        200: eventStreamResponse('The command, streamed. Frames are `start`, `log`, `error` and `done`.'),
        400: { $ref: 'Problem#', description: 'Empty command, or a working directory outside the checkout.' },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        403: { $ref: 'Problem#', description: 'The shell is switched off in this deployment.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }
    if (!config.app.adminShell) {
      return reply.status(403).send(problem(
        403,
        'The shell is switched off',
        'GIAM_ADMIN_SHELL is false in this deployment, so no arbitrary command runs here.',
      ));
    }

    const { command, cwd } = request.body as { command: string; cwd?: string };
    if (!command?.trim()) {
      return reply.status(400).send(problem(400, 'Bad Request', 'command is required.'));
    }

    const root = path.resolve(PROJECT_ROOT);
    const workDir = cwd?.trim() ? path.resolve(root, cwd.trim()) : root;
    // Compared as a path rather than as a string: a prefix test lets "/srv/giam-anything" pass for
    // "/srv/giam", and a relative result starting with ".." is the escape this is here to catch.
    const relative = path.relative(root, workDir);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      return reply.status(400).send(problem(400, 'Bad Request', 'cwd must resolve inside the checkout.'));
    }

    appendLog(`[${new Date().toISOString()}] ADMIN shell command from ${request.ip}: ${command.slice(0, 200)}`);
    const raw = beginSSE(reply, request);
    await streamProcess(raw, command, [], workDir, 'shell');
  });

  fastify.get('/logs/stream', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'streamAdminLogs',
      tags: ['admin'],
      summary: 'Watch the log buffer as it fills',
      description:
        `${NO_STANDARD} Sends the buffered lines, then every new one as it arrives. A comment frame `
        + 'every fifteen silent seconds keeps a proxy from dropping an idle stream, which would leave '
        + 'the console showing a service that had simply stopped being watched. Reconnect with '
        + '`snapshot=false` so the lines already held are not sent a second time. Messages are length '
        + 'capped and never carry a stack, because a stack from this service can carry a credential.',
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          snapshot: { type: 'string', enum: ['true', 'false'], default: 'true' },
        },
      },
      response: {
        200: eventStreamResponse('The log stream. Each frame is a `log` event carrying one line.'),
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    const raw = beginSSE(reply, request);
    let lastSentAt = Date.now();
    const write = (frame: string) => {
      try { raw.write(frame); lastSentAt = Date.now(); } catch { /* socket gone */ }
    };
    const sendLine = (line: string) => write(`event: log\ndata: ${JSON.stringify({ text: line })}\n\n`);

    const { snapshot } = request.query as { snapshot?: string };
    if (snapshot !== 'false') readLogs().forEach(sendLine);

    let seen = writeCount();
    const poll = setInterval(() => {
      if (!raw.writable) { clearInterval(poll); return; }
      const current = writeCount();
      if (current > seen) {
        const fresh = Math.min(current - seen, logBufferLength());
        readLogs(fresh).forEach(sendLine);
        seen = current;
      } else if (Date.now() - lastSentAt >= SSE_HEARTBEAT_MS) {
        write(SSE_HEARTBEAT_FRAME);
      }
    }, 2000);

    request.raw.on('close', () => clearInterval(poll));
    await new Promise<void>(() => { /* held open until the operator disconnects */ });
  });

  fastify.get('/system', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'getAdminSystem',
      tags: ['admin'],
      summary: 'The running system: host, runtime, package and configuration',
      description:
        `${NO_STANDARD} What this process actually is, so a question about behaviour can be answered `
        + 'against the running configuration rather than against what somebody believes was deployed. '
        + 'Any variable whose NAME suggests a secret is replaced with `***` and a connection string '
        + 'keeps everything but its password: a screenshot of this page travels further than the page.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'The running system.',
          type: 'object',
          additionalProperties: true,
          properties: {
            os: { type: 'object', additionalProperties: true },
            node: { type: 'object', additionalProperties: true },
            package: { type: 'object', additionalProperties: true },
            env: { type: 'object', additionalProperties: { type: 'string' } },
            dotenvKeys: { type: 'array', items: { type: 'string' } },
          },
          examples: [{
            os: { platform: 'linux', cpus: 4 },
            node: { version: 'v22.12.0', uptimeSeconds: 812 },
            package: { name: 'giam-backend', version: '1.0.0' },
            env: { GIAM_DB_NAME: 'giamdb', GIAM_ADMIN_TOKEN: '***' },
            dotenvKeys: ['GIAM_DB_NAME'],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    let pkg: Record<string, unknown>;
    try {
      const raw = JSON.parse(fs.readFileSync(path.join(BACKEND_ROOT, 'package.json'), 'utf-8'));
      pkg = { name: raw.name, version: raw.version, description: raw.description, scripts: raw.scripts ?? {} };
    } catch {
      pkg = { error: 'The package file could not be read.' };
    }

    const env: Record<string, string> = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (value === undefined) continue;
      if (isConnectionString(key, value)) env[key] = maskConnectionString(value);
      else if (isSensitive(key)) env[key] = '***';
      else env[key] = value;
    }

    return reply.send({
      os: {
        platform: os.platform(),
        arch: os.arch(),
        release: os.release(),
        hostname: os.hostname(),
        type: os.type(),
        cpus: os.cpus().length,
        totalMemoryMB: Math.round(os.totalmem() / 1024 / 1024),
        freeMemoryMB: Math.round(os.freemem() / 1024 / 1024),
        uptime: Math.round(os.uptime()),
      },
      node: {
        version: process.version,
        execPath: process.execPath,
        pid: process.pid,
        cwd: process.cwd(),
        projectRoot: PROJECT_ROOT,
        uptimeSeconds: Math.round(process.uptime()),
        instanceId: config.keys.instanceId,
      },
      package: pkg,
      env,
      dotenvKeys: readEnvKeys(),
    });
  });

  fastify.patch('/env', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'updateAdminEnv',
      tags: ['admin'],
      summary: 'Change one configuration variable',
      description:
        `${NO_STANDARD} Writes one key into the checkout's environment file and applies it to this `
        + 'process at once. Most of what reads configuration reads it at start-up, so the answer '
        + 'always says a reload is needed rather than pretending the change took full effect.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['key', 'value'],
        properties: {
          key: { type: 'string', examples: ['GIAM_DB_NAME'] },
          value: { type: 'string', examples: ['giamdb'] },
        },
      },
      response: {
        200: {
          description: 'Written.',
          type: 'object',
          additionalProperties: false,
          required: ['updated', 'reloadRequired'],
          properties: {
            updated: { type: 'boolean' },
            reloadRequired: { type: 'boolean' },
          },
          examples: [{ updated: true, reloadRequired: true }],
        },
        400: { $ref: 'Problem#', description: 'The key or the value is not writable to an environment file.' },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    const { key, value } = request.body as { key: string; value: string };
    if (!ENV_KEY.test(key)) {
      return reply.status(400).send(problem(400, 'Bad Request', 'A key is letters, digits and underscores.'));
    }
    if (/[\r\n]/.test(value)) {
      return reply.status(400).send(problem(400, 'Bad Request', 'A value cannot contain a line break.'));
    }

    try {
      writeEnvKey(key, value);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      appendLog(`[${new Date().toISOString()}] ERROR ADMIN could not write ${key} to ${ENV_PATH}: ${reason}`);
      return reply.status(400).send(problem(400, 'Bad Request', `The environment file could not be written: ${reason}`));
    }
    process.env[key] = value;
    // The value is deliberately absent: this is the one route whose argument is often a secret.
    appendLog(`[${new Date().toISOString()}] ADMIN configuration key "${key}" changed from ${request.ip}`);

    return reply.send({ updated: true, reloadRequired: true });
  });

  fastify.post('/restart', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'restartAdminTarget',
      tags: ['admin'],
      summary: 'Restart the service or the console',
      description:
        `${NO_STANDARD} The service answers first and then exits, so whatever supervises it starts it `
        + 'again; under a watcher or an orchestrator that is a restart, and with neither it is a stop, '
        + 'which is why the answer says what it did rather than what it achieved. The console is ended '
        + 'by port and started again.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['target'],
        properties: {
          target: { type: 'string', enum: ['backend', 'frontend'], examples: ['backend'] },
        },
      },
      response: {
        200: {
          description: 'The restart was started.',
          type: 'object',
          additionalProperties: false,
          required: ['ok', 'message'],
          properties: { ok: { type: 'boolean' }, message: { type: 'string' } },
          examples: [{ ok: true, message: 'The service is exiting so its supervisor restarts it.' }],
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    const { target } = request.body as { target: 'backend' | 'frontend' };

    if (target === 'frontend') {
      const port = frontendPort();
      killProcessOnPort(port);
      await new Promise((done) => setTimeout(done, 600));
      spawnFrontend();
      appendLog(`[${new Date().toISOString()}] ADMIN console restart started on port ${port}`);
      return reply.send({ ok: true, message: `The console is restarting on port ${port}.` });
    }

    appendLog(`[${new Date().toISOString()}] ADMIN service restart requested from ${request.ip}`);
    await reply.send({ ok: true, message: 'The service is exiting so its supervisor restarts it.' });
    setTimeout(() => process.exit(0), 800);
  });

  fastify.post('/reload', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'reloadAdminRuntime',
      tags: ['admin'],
      summary: 'Rebuild the datastore runtime without restarting',
      description:
        `${NO_STANDARD} Re-reads the configuration and rebuilds the encrypted client and the event bus `
        + 'in place. After the database has been dropped and built again this process still holds a '
        + 'client bound to a key vault that no longer exists, and every encrypted read fails with a '
        + 'message about unsatisfied keys. On a host that cannot be restarted this is the way back.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'The runtime was rebuilt.',
          type: 'object',
          additionalProperties: false,
          required: ['ok', 'message', 'steps'],
          properties: {
            ok: { type: 'boolean' },
            message: { type: 'string' },
            steps: { type: 'array', items: { type: 'string' } },
          },
          examples: [{ ok: true, message: 'The runtime was rebuilt.', steps: ['re-wired against database "giamdb"'] }],
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        429: { $ref: 'Problem#', description: 'Too many requests from this address.' },
        500: { $ref: 'Problem#', description: 'The runtime could not be rebuilt; the reason is in the log.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const limit = limitOperations(request.ip ?? 'unknown');
    if (!limit.allowed) {
      reply.header('Retry-After', String(limit.retryAfter));
      return reply.status(429).send(problem(429, 'Too Many Requests', `Retry after ${limit.retryAfter}s.`));
    }

    appendLog(`[${new Date().toISOString()}] ADMIN runtime reload requested from ${request.ip}`);
    try {
      const { steps } = await reloadDbRuntime(fastify);
      for (const step of steps) appendLog(`[${new Date().toISOString()}] ADMIN reload: ${step}`);
      return reply.send({ ok: true, message: 'The runtime was rebuilt.', steps });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      appendLog(`[${new Date().toISOString()}] ERROR ADMIN reload failed: ${reason.slice(0, 300)}`);
      return reply.status(500).send(problem(500, 'The runtime could not be rebuilt', reason.slice(0, 300)));
    }
  });
}
