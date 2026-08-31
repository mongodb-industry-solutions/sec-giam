import { FastifyInstance } from 'fastify';
import { config } from '../../../config';

// Infrastructure, not API. Open so a deployment probe can reach it, and deliberately silent about
// anything an unauthenticated caller has no business learning.
export async function systemController(fastify: FastifyInstance) {
  fastify.get('/health', {
    schema: {
      operationId: 'getSystemHealth',
      tags: ['system'],
      summary: 'Health check',
      description:
        'No applicable standard for the enclosing API; the response body follows the IETF '
        + 'health+json draft, reporting the `mongodb:connectivity` check. Public, for deployment probes.',
      // Explicitly public: a deployment probe cannot present a credential.
      security: [],
      response: {
        200: {
          description: 'The service is serving and its datastore answered.',
          type: 'object',
          additionalProperties: true,
          examples: [{ status: 'pass', serviceId: 'giam', checks: {} }],
        },
        503: {
          description: 'The datastore is unreachable, so protected routes will refuse rather than fail.',
          type: 'object',
          additionalProperties: true,
          examples: [{ status: 'fail', serviceId: 'giam', checks: {} }],
        },
      },
    },
  }, async (_request, reply) => {
    const now = new Date().toISOString();
    reply.header('Content-Type', 'application/health+json; charset=utf-8');
    const detail = { database: config.mongodb.dbName };

    if (fastify.dbError) {
      return reply.status(503).send({
        status: 'fail',
        serviceId: 'giam',
        detail,
        checks: {
          'mongodb:connectivity': [
            { status: 'fail', componentType: 'datastore', output: fastify.dbError, time: now },
          ],
        },
      });
    }

    try {
      const started = Date.now();
      await fastify.db.command({ ping: 1 });
      return reply.send({
        status: 'pass',
        serviceId: 'giam',
        detail,
        checks: {
          'mongodb:connectivity': [
            {
              status: 'pass',
              componentType: 'datastore',
              observedValue: Date.now() - started,
              observedUnit: 'ms',
              time: now,
            },
          ],
        },
      });
    } catch (err) {
      return reply.status(503).send({
        status: 'fail',
        serviceId: 'giam',
        detail,
        checks: {
          'mongodb:connectivity': [
            {
              status: 'fail',
              componentType: 'datastore',
              output: err instanceof Error ? err.message : 'ping failed',
              time: now,
            },
          ],
        },
      });
    }
  });
}
