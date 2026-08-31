import { FastifyInstance } from 'fastify';
import { readLogs } from '../../../shared/services/logBuffer';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { buildPostureReport } from '../services/posture.service';

// Operational diagnostics. Not part of the integration contract, and behind the administrative
// credential: a log buffer from an identity service is not something to publish.
export async function adminController(fastify: FastifyInstance) {
  fastify.get('/posture', {
    schema: {
      operationId: 'getAdminPosture',
      tags: ['admin'],
      summary: 'Effective security posture',
      description:
        'No applicable standard. Reports the security properties actually in force: key custody and '
        + 'whether it is external, replica awareness, the token validation models available, proof of '
        + 'possession support, whether attestation is required, and storage health. This exists '
        + 'INSTEAD of gating capabilities by environment: GIAM does not decide what an operator may '
        + 'run, it makes what is running impossible to misread. A weaker configuration is reported '
        + 'as `degraded` with a machine-readable code and a remedy, and the service keeps serving.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'The posture in force. `degraded` still means serving.',
          type: 'object',
          additionalProperties: true,
          required: ['status', 'findings'],
          properties: {
            status: { type: 'string', enum: ['ok', 'degraded'] },
            instanceId: { type: 'string' },
            keyCustody: { type: 'object', additionalProperties: true },
            tokenValidation: { type: 'object', additionalProperties: true },
            proofOfPossession: { type: 'object', additionalProperties: true },
            attestation: { type: 'object', additionalProperties: true },
            storage: { type: 'object', additionalProperties: true },
            administration: { type: 'object', additionalProperties: true },
            findings: {
              type: 'array',
              items: {
                type: 'object',
                required: ['code', 'level', 'detail', 'remedy'],
                properties: {
                  code: { type: 'string' },
                  level: { type: 'string', enum: ['ok', 'degraded'] },
                  detail: { type: 'string' },
                  remedy: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            status: 'ok',
            instanceId: 'giam-0',
            keyCustody: { provider: 'instance-local', externalCustody: false, multiReplicaCapable: true, declaredReplicas: 3 },
            findings: [],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid administrative token was presented.' },
        503: { $ref: 'Problem#', description: 'No administrative credential is configured.' },
      },
    },
    preHandler: requireAdmin,
  }, async () => buildPostureReport({
    // Deliberately answerable while the database is down: an operator asking why the service is
    // degraded needs the report most at exactly that moment.
    databaseReachable: fastify.dbError === null,
    databaseError: fastify.dbError,
  }));

  fastify.get('/logs', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'getAdminLogs',
      tags: ['admin'],
      summary: 'Recent log lines',
      description:
        'No applicable standard. Ring buffer of recent lines, warnings and above plus request '
        + 'summaries, so a degraded service is diagnosable without pod access. Messages are length '
        + 'capped and never carry a stack, because a stack from this service can carry a credential.',
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          limit: { type: 'integer', minimum: 1, maximum: 500, default: 200, examples: [50] },
        },
      },
      response: {
        200: {
          description: 'The most recent lines, oldest first.',
          type: 'object',
          additionalProperties: false,
          required: ['lines'],
          properties: { lines: { type: 'array', items: { type: 'string' } } },
          examples: [{ lines: ['[2026-08-28T10:00:00.000Z] STARTUP giam is up'] }],
        },
        401: { $ref: 'Problem#', description: 'No valid administrative token was presented.' },
        503: { $ref: 'Problem#', description: 'No administrative credential is configured.' },
      },
    },
  }, async (request) => {
    const { limit } = request.query as { limit?: number };
    return { lines: readLogs(limit ?? 200) };
  });
}
