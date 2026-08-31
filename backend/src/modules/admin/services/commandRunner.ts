import { spawn, execSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import * as path from 'path';
import type { ServerResponse } from 'http';
import { appendLog } from '../../../shared/services/logBuffer';
import { SSE_HEARTBEAT_FRAME, SSE_HEARTBEAT_MS } from '../../../shared/services/sse';
import { config } from '../../../config';

/**
 * Running maintenance from the console, without turning the console into a shell.
 *
 * The scripts an operator may run are NAMED here. The tempting version takes a script name and passes
 * it to npm, and it is exactly wrong: a package file is editable, so "any script in package.json"
 * means "anything at all" one commit later. Naming each one means a new capability is a decision
 * somebody made rather than a consequence of a parameter.
 */

/** Walks up from the compiled or source location until the backend's own package file is found. */
function findBackendRoot(): string {
  let current = __dirname;
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = path.join(current, 'package.json');
    if (existsSync(candidate)) {
      try {
        if (JSON.parse(readFileSync(candidate, 'utf-8')).name === 'giam-backend') return current;
      } catch { /* not readable as a package file, keep walking */ }
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  // Source layout: src/modules/admin/services -> backend.
  return path.resolve(__dirname, '../../../..');
}

export const BACKEND_ROOT: string = findBackendRoot();
export const PROJECT_ROOT: string = config.app.projectRoot ?? path.dirname(BACKEND_ROOT);

/**
 * Every script the console may run. They are the checkout's own, run from its root, so the console
 * does exactly what an operator at a terminal would do and there is no second definition of "setup"
 * to drift from the first.
 */
export const ALLOWED_COMMANDS: Record<string, { args: string[]; summary: string }> = {
  setup: {
    args: ['run', 'setup'],
    summary: 'Install every dependency, in the shared packages and in both applications',
  },
  'setup:key:master': {
    args: ['run', 'setup:key:master'],
    summary: 'Generate the local master key the encrypted collections are keyed from',
  },
  'setup:db': {
    args: ['run', 'setup:db'],
    summary: 'Create collections and indexes and provision the data encryption keys',
  },
  'setup:db:reset': {
    args: ['run', 'setup:db:reset'],
    summary: 'Rebuild the database, its key vault and its keys from nothing',
  },
  'setup:seed': {
    args: ['run', 'setup:seed'],
    summary: 'Load the reference and demonstration records',
  },
  'setup:reset': {
    args: ['run', 'setup:reset'],
    summary: 'Rebuild the database and load the records again, in one run',
  },
  'setup:check': {
    args: ['run', 'setup:check'],
    summary: 'Report collections, document counts, indexes, encrypted fields and key state',
  },
  'setup:db:drop': {
    args: ['run', 'setup:db:drop'],
    summary: 'Drop the database, and with it the key vault that only serves it',
  },
  test: { args: ['run', 'test'], summary: 'Run every suite' },
  'test:unit': { args: ['run', 'test:unit'], summary: 'Run the unit suite' },
  'test:integration': { args: ['run', 'test:integration'], summary: 'Run the integration suite' },
  'type-check': { args: ['run', 'type-check'], summary: 'Type-check every project without emitting' },
  openapi: {
    args: ['run', 'openapi'],
    summary: 'Regenerate the API document and check it against the documentation rules',
  },
};

/** The npm entry point. On Windows the shell resolves the shim, so the plain name is enough. */
const NPM = 'npm';

export interface StreamOptions {
  env?: NodeJS.ProcessEnv;
  /** False while this run is one step of a longer sequence: the stream stays open for the next one. */
  finalize?: boolean;
  /** Called once the child exits. Anything returned is sent as a `summary` frame before `done`. */
  summarize?: () => unknown | null;
}

/**
 * Runs a child process and streams its output as server-sent events.
 *
 * The socket may already be gone (the operator navigated away, a proxy dropped the stream). Writing
 * to it must never take down the run, which keeps going to completion on the server either way.
 */
export function streamProcess(
  raw: ServerResponse,
  command: string,
  args: string[],
  cwd: string,
  label: string,
  options: StreamOptions = {},
): Promise<number> {
  const finalize = options.finalize !== false;
  const write = (frame: string) => {
    try { raw.write(frame); } catch { /* socket gone, the child still finishes */ }
  };
  const send = (type: string, text: string) => {
    write(`event: ${type}\ndata: ${JSON.stringify({ text })}\n\n`);
    appendLog(`[${new Date().toISOString()}] ADMIN [${label}] ${text.slice(0, 400)}`);
  };

  // A long silent step leaves the stream idle for minutes and an ingress drops an idle connection, so
  // the browser never receives the terminating frame and the panel spins on a run that already ended.
  const heartbeat = setInterval(() => write(SSE_HEARTBEAT_FRAME), SSE_HEARTBEAT_MS);

  send('start', `> ${command} ${args.join(' ')}  (cwd: ${cwd})`);

  const child = spawn(command, args, { cwd, shell: true, env: { ...process.env, ...(options.env ?? {}) } });

  return new Promise((resolve) => {
    child.stdout.on('data', (chunk: Buffer) => {
      chunk.toString().split('\n').filter(Boolean).forEach((line) => send('log', line));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      chunk.toString().split('\n').filter(Boolean).forEach((line) => send('error', line));
    });
    child.on('close', (code, signal) => {
      clearInterval(heartbeat);
      // A process killed by a signal reports a null code. Treating that as zero would report an
      // aborted run as a successful one.
      const exitCode = code ?? (signal ? 1 : 0);
      if (options.summarize) {
        try {
          const summary = options.summarize();
          if (summary) write(`event: summary\ndata: ${JSON.stringify(summary)}\n\n`);
        } catch (err) {
          send('error', `The result report could not be read: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      if (finalize) {
        send('done', signal ? `Process terminated by signal ${signal}` : `Process exited with code ${exitCode}`);
        raw.end?.();
      }
      resolve(exitCode);
    });
    child.on('error', (err) => {
      clearInterval(heartbeat);
      send('error', `Failed to start: ${err.message}`);
      if (finalize) raw.end?.();
      resolve(-1);
    });
  });
}

/** Runs one allowlisted script from the checkout root. */
export function runAllowedCommand(
  raw: ServerResponse,
  name: string,
  args?: string[],
  summarize?: () => unknown | null,
): Promise<number> {
  return streamProcess(raw, NPM, args ?? ALLOWED_COMMANDS[name].args, PROJECT_ROOT, `npm:${name}`, { summarize });
}

/** Runs one step of a longer sequence, leaving the stream open for the next. */
export function runSequenceStep(raw: ServerResponse, label: string, args: string[]): Promise<number> {
  return streamProcess(raw, NPM, args, PROJECT_ROOT, `npm:${label}`, { finalize: false });
}

/** The console's own port, parsed from where the frontend is configured to be. */
export function frontendPort(): number {
  try {
    const port = new URL(config.server.frontendUrl).port;
    return port ? parseInt(port, 10) : 8086;
  } catch {
    return 8086;
  }
}

/** Cross-platform: ends whatever is listening on a port, so a fresh one can take it. */
export function killProcessOnPort(port: number): void {
  try {
    if (process.platform === 'win32') {
      const out = execSync(`netstat -ano | findstr ":${port} "`, { encoding: 'utf-8', shell: 'cmd.exe' });
      for (const line of out.split('\n')) {
        if (!/LISTEN/i.test(line)) continue;
        const pid = line.trim().split(/\s+/).pop() ?? '';
        if (/^\d+$/.test(pid) && pid !== '0') {
          try { execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' }); } catch { /* already gone */ }
        }
      }
    } else {
      const pids = execSync(`lsof -ti:${port} -sTCP:LISTEN 2>/dev/null || echo ''`, { encoding: 'utf-8', shell: '/bin/sh' })
        .trim().split('\n').filter(Boolean);
      for (const pid of pids) {
        try { process.kill(parseInt(pid, 10), 'SIGTERM'); } catch { /* already gone */ }
      }
    }
  } catch { /* nothing listening, nothing to end */ }
}

/** Starts the console's dev server again, detached, so it outlives this request. */
export function spawnFrontend(): void {
  const child = spawn(NPM, ['run', 'dev'], {
    cwd: path.join(PROJECT_ROOT, 'frontend'),
    detached: true,
    stdio: 'ignore',
    shell: true,
    env: { ...process.env },
  });
  child.unref();
}
