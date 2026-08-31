import dotenv from 'dotenv';
import { resolve } from 'path';

// The repo root .env, three levels up from giam/backend/src/.
dotenv.config({ path: resolve(__dirname, '../../../.env') });

import Fastify, { FastifyInstance } from 'fastify';
import corsPlugin from './plugins/cors';
import correlationPlugin from './plugins/correlation';
import mongodbPlugin from './plugins/mongodb';
import swaggerPlugin from './plugins/swagger';
import { appendLog, appendLogEntry, levelLabel, mirrorConsoleToLogBuffer } from './shared/services/logBuffer';
import { configurationReport, readinessReport, formatReport } from './shared/services/startupReport';
import { PROBLEM_SCHEMA, OAUTH_ERROR_SCHEMA, problem, isOAuthSurface, oauthError } from './shared/models/problem';
import { realmModule } from './modules/realm';
import { directoryModule } from './modules/directory';
import { provisioningModule } from './modules/provisioning';
import { authenticationModule } from './modules/authentication';
import { oauthModule } from './modules/oauth';
import { consentModule } from './modules/consent';
import { authorizationModule } from './modules/authorization';
import { workloadModule } from './modules/workload';
import { privilegeModule } from './modules/privilege';
import { keysModule } from './modules/keys';
import { auditModule } from './modules/audit';
import { adminModule } from './modules/admin';
import { systemModule } from './modules/system';
import { registerBuiltinPorts } from './shared/ports/builtins';
import { config } from './config';

declare module 'fastify' {
  interface FastifyInstance {
    // Every route the server will serve, collected as it is registered. The API document is checked
    // against this list, so an endpoint cannot exist without an entry in the contract.
    registeredRoutes: Array<{ method: string; url: string }>;
  }
}

export interface BuildOptions {
  /**
   * Build the routes and the API document without connecting to a database.
   *
   * Used to emit and lint the OpenAPI document, which must be possible with nothing else running:
   * a contract that can only be produced by a working deployment is a contract that stops being
   * checked the moment the deployment is inconvenient.
   */
  skipDatabase?: boolean;
}

export async function buildApp(options: BuildOptions = {}): Promise<FastifyInstance> {
  mirrorConsoleToLogBuffer();
  // Every shipped implementation, registered by name. Which one is used is configuration.
  registerBuiltinPorts();

  const fastify = Fastify({
    logger: {
      // Mirror every warn and above into the ring buffer whatever the call site: a handler that logs
      // and answers 500 without throwing never reaches the onError hook.
      hooks: {
        logMethod(args: unknown[], method: (...a: unknown[]) => void, level: number) {
          if (level >= 40) appendLogEntry(levelLabel(level), args);
          return method.apply(this, args);
        },
      },
    },
    pluginTimeout: 60000,
    ajv: { customOptions: { keywords: ['example'] } },
  });

  // Before any module registers: the onRoute hook only fires for routes added after it.
  fastify.decorate('registeredRoutes', [] as Array<{ method: string; url: string }>);
  fastify.addHook('onRoute', (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) fastify.registeredRoutes.push({ method, url: route.url });
  });

  // Referenced by every route that can fail on the REST surface, so the shape is declared once.
  fastify.addSchema(PROBLEM_SCHEMA);
  fastify.addSchema(OAUTH_ERROR_SCHEMA);

  // RFC 6749 requires form encoding on the token endpoint, and the specification is not offering a
  // choice: a JSON body there is a non-conforming server that happens to work with one client.
  fastify.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string' },
    (_request, body, done) => {
      try {
        const params = new URLSearchParams(body as string);
        done(null, Object.fromEntries(params.entries()));
      } catch (err) {
        done(err as Error, undefined);
      }
    },
  );

  await fastify.register(correlationPlugin);
  await fastify.register(corsPlugin);
  await fastify.register(swaggerPlugin);
  if (options.skipDatabase) {
    fastify.decorate('db', null as never);
    fastify.decorate('dbError', 'database intentionally not connected');
  } else {
    await fastify.register(mongodbPlugin);
  }

  // Protected routes refuse with 503 rather than 401 when the datastore is gone, so an operator reads
  // "the directory is unreachable" instead of chasing a credentials problem that does not exist.
  fastify.addHook('preHandler', async (request, reply) => {
    const url = request.url;
    const isProbe = url === '/health' || url.startsWith('/api/v1/system/health');
    if (fastify.dbError !== null && !isProbe && !url.startsWith('/doc') && !url.startsWith('/admin/posture')) {
      return reply.status(503).send(problem(503, 'Service unavailable', fastify.dbError));
    }
  });

  // Errors keep the shape of the surface they occurred on: the specification's own on a standard
  // endpoint, RFC 9457 problem+json everywhere else. A house envelope on an OAuth endpoint is a defect.
  fastify.setErrorHandler((error, request, reply) => {
    const validation = (error as { validation?: Array<{ instancePath?: string; message?: string }> }).validation;
    const failure = error as { statusCode?: number; message?: string };
    const status = validation?.length ? 400 : failure.statusCode ?? 500;

    if (isOAuthSurface(request.url)) {
      return reply.status(status).send(oauthError(status, validation?.length
        ? validation.map((i) => `${i.instancePath || 'body'} ${i.message ?? 'is invalid'}`.trim()).join('; ')
        : failure.message));
    }

    if (validation?.length) {
      const detail = validation
        .map((issue) => `${issue.instancePath || 'body'} ${issue.message ?? 'is invalid'}`.trim())
        .join('; ');
      reply.header('Content-Type', 'application/problem+json; charset=utf-8');
      return reply.status(400).send(problem(400, 'Bad Request', detail));
    }

    reply.header('Content-Type', 'application/problem+json; charset=utf-8');
    // Never a stack and never an internal message on a 500: this service's internals are its secrets.
    return reply.status(status).send(status >= 500
      ? problem(500, 'Internal Server Error')
      : problem(status, failure.message ?? 'Request failed'));
  });

  fastify.addHook('onResponse', (request, reply, done) => {
    appendLog(
      `[${new Date().toISOString()}] ${request.method} ${request.url} -> ${reply.statusCode}`
      + ` (${reply.elapsedTime.toFixed(0)}ms) [${request.correlationId}]`,
    );
    done();
  });

  fastify.addHook('onError', (request, reply, error, done) => {
    const status = (error as { statusCode?: number }).statusCode ?? reply.statusCode ?? 500;
    const message = (error.message || '').replace(/\s+/g, ' ').slice(0, 500);
    appendLog(
      `[${new Date().toISOString()}] ERROR ${request.method} ${request.url} -> ${status} `
      + `[${request.correlationId}] ${error.name || 'Error'}: ${message}`,
    );
    done();
  });

  fastify.get('/', {
    schema: {
      operationId: 'getRoot',
      tags: ['system'],
      summary: 'Redirect to the API documentation',
      description: 'No applicable standard. Convenience redirect to /doc.',
      // Explicitly no security, rather than security omitted. The two read the same in a diff and
      // mean opposite things, and only one of them is a decision.
      security: [],
      response: { 302: { description: 'Redirect to /doc', type: 'null' } },
    },
  }, async (_request, reply) => reply.redirect('/doc'));

  // Infra probes expect this exact path, alongside the module's fuller report.
  fastify.get('/health', {
    schema: {
      operationId: 'getHealth',
      tags: ['system'],
      summary: 'Health check (standard alias)',
      description: 'No applicable standard for the enclosing API; the body follows IETF health+json.',
      // Explicitly public: a deployment probe cannot present a credential.
      security: [],
      response: {
        200: {
          description: 'Serving.',
          type: 'object',
          additionalProperties: true,
          examples: [{ status: 'pass', serviceId: 'giam', checks: {} }],
        },
        503: {
          description: 'Degraded.',
          type: 'object',
          additionalProperties: true,
          examples: [{ status: 'fail', serviceId: 'giam', checks: {} }],
        },
      },
    },
  }, async (_request, reply) => {
    reply.header('Content-Type', 'application/health+json; charset=utf-8');
    const now = new Date().toISOString();
    if (fastify.dbError) {
      return reply.status(503).send({
        status: 'fail',
        serviceId: 'giam',
        checks: { 'mongodb:connectivity': [{ status: 'fail', componentType: 'datastore', output: fastify.dbError, time: now }] },
      });
    }
    try {
      const started = Date.now();
      await fastify.db.command({ ping: 1 });
      return reply.send({
        status: 'pass',
        serviceId: 'giam',
        checks: { 'mongodb:connectivity': [{ status: 'pass', componentType: 'datastore', observedValue: Date.now() - started, observedUnit: 'ms', time: now }] },
      });
    } catch (err) {
      return reply.status(503).send({
        status: 'fail',
        serviceId: 'giam',
        checks: { 'mongodb:connectivity': [{ status: 'fail', componentType: 'datastore', output: err instanceof Error ? err.message : 'ping failed', time: now }] },
      });
    }
  });

  // Protocol surfaces first: they are what a consumer integrates against.
  await fastify.register(oauthModule);
  await fastify.register(authenticationModule);
  await fastify.register(consentModule);
  await fastify.register(keysModule);
  await fastify.register(workloadModule);
  await fastify.register(provisioningModule);
  // Then the administrative ones.
  await fastify.register(realmModule);
  await fastify.register(directoryModule);
  await fastify.register(authorizationModule);
  await fastify.register(privilegeModule);
  await fastify.register(auditModule);
  await fastify.register(adminModule);
  await fastify.register(systemModule, { prefix: '/api/v1' });

  return fastify;
}

