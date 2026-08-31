import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { IDENTITY_COLLECTION } from '../../../shared/models/collections';
import { IdentityRecord } from '../../directory/models/identity.model';
import { problem } from '../../../shared/models/problem';

/**
 * Reconciliation: the half that makes best-effort delivery safe.
 *
 * A consumer asks what this authority currently believes about a set of principals, and corrects
 * itself. That is what covers the case where a push failed, an endpoint was down, or a consumer was
 * restored from a backup taken before a suspension.
 *
 * It is a PULL on purpose. A consumer knows which principals it holds; this authority does not, and
 * pushing the whole directory at everyone to be safe would be both wasteful and a disclosure. Asking
 * about the ones you have is narrower in every direction.
 */
export async function reconcileController(fastify: FastifyInstance) {
  fastify.post('/realms/:realm/provisioning/reconcile', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'reconcileProvisioning',
      tags: ['provisioning'],
      summary: 'What this authority currently believes about these principals',
      description:
        'No applicable standard; SCIM covers the write path, not this. A consumer sends the principals '
        + 'it holds and receives their current lifecycle state, which is what corrects a missed push '
        + 'without waiting for the next one. Answering only about the principals asked for keeps this '
        + 'from becoming a way to enumerate the directory.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['subjectIds'],
        additionalProperties: false,
        properties: {
          subjectIds: {
            type: 'array',
            maxItems: 1000,
            items: { type: 'string' },
            description: 'The principals the consumer holds. Bounded, so this cannot be used to sweep the directory.',
          },
        },
      },
      response: {
        200: {
          description: 'The current state of each principal asked about.',
          type: 'object',
          additionalProperties: false,
          required: ['principals', 'unknown'],
          properties: {
            principals: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  subjectId: { type: 'string' },
                  active: { type: 'boolean' },
                  lifecycleState: { type: 'string' },
                  version: { type: 'integer' },
                },
              },
            },
            unknown: {
              type: 'array',
              items: { type: 'string' },
              description: 'Asked about but not held here. A consumer holding one of these should stop.',
            },
          },
          examples: [{
            principals: [{ subjectId: 'sub-9f21', active: false, lifecycleState: 'suspended', version: 4 }],
            unknown: ['sub-0000'],
          }],
        },
        401: { $ref: 'Problem#', description: 'No provisioning credential.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        503: { $ref: 'Problem#', description: 'The provisioning surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const { subjectIds } = request.body as { subjectIds: string[] };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const held = await fastify.db.collection<IdentityRecord>(IDENTITY_COLLECTION)
      .find(
        { realmId: realm.realmId, subjectId: { $in: subjectIds } },
        { projection: { _id: 0, subjectId: 1, active: 1, lifecycleState: 1, meta: 1 } },
      )
      .toArray();

    const found = new Set(held.map((identity) => identity.subjectId));
    return reply.send({
      principals: held.map((identity) => ({
        subjectId: identity.subjectId,
        active: identity.active,
        lifecycleState: identity.lifecycleState,
        version: identity.meta?.version ?? 0,
      })),
      // Told explicitly rather than left out. A consumer holding a principal this authority does not
      // have is the case most worth surfacing, and silence reads as "unchanged".
      unknown: subjectIds.filter((subjectId) => !found.has(subjectId)),
    });
  });
}
