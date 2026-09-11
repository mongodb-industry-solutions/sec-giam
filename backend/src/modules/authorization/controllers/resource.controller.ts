import { FastifyInstance } from 'fastify';
import { REALM_COLLECTION } from '../../../shared/models/collections';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { problem } from '../../../shared/models/problem';
import { ResourceRecord } from '../models/resource.model';
import { ResourceAdminService } from '../services/resourceAdmin.service';
import { resourceServerView } from './resourceCatalog.controller';

/**
 * Where a protected application declares what it enforces, admin-token gated for its own deployment.
 *
 * The direction is the whole arrangement: the application ships its enforcement points in its own
 * code and PUTs them here, because only the code containing a guard can say the permission exists.
 * The authority then decides who holds them. Neither side can invent the other's half, and an
 * application that tried to grant itself something would be writing to a collection it cannot reach.
 *
 * The write itself lives in `ResourceAdminService.registerCatalog`, shared with the RBAC-gated
 * equivalent in `resourceCatalog.controller.ts`: one caller is a resource server's own deployment
 * script running with no realm session at all, the other is a signed-in operator with
 * `permissions:manage`, and both must reach the identical, idempotent write rather than two that
 * could drift apart.
 */
export async function resourceController(fastify: FastifyInstance) {
  fastify.put('/admin/resource-servers/:name/permissions', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'registerResourceServerPermissions',
      tags: ['authorization'],
      summary: 'Register a resource server permission catalog',
      description:
        'No applicable standard. A protected application declares the enforcement points it ships, '
        + 'and the authority records them so roles can be granted over them. Idempotent and '
        + 'versioned: registering the same catalog twice is one registration, and a permission that '
        + 'disappears is marked deprecated rather than deleted, because existing grants reference it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['name'],
        properties: { name: { type: 'string', examples: ['orders-api'] } },
      },
      body: {
        type: 'object',
        required: ['audience', 'permissions'],
        additionalProperties: false,
        properties: {
          name: { type: 'string' },
          realm: { type: 'string', description: 'Defaults to the realm whose name matches the audience.' },
          audience: { type: 'string', examples: ['orders-api'] },
          catalogVersion: { type: 'integer', examples: [3] },
          validationMode: { type: 'string', enum: ['local-jwks', 'introspection', 'hybrid'] },
          permissions: {
            type: 'array',
            items: {
              type: 'object',
              required: ['resource', 'action'],
              additionalProperties: false,
              properties: {
                resource: { type: 'string' },
                action: { type: 'string' },
                description: { type: 'string' },
              },
            },
          },
        },
      },
      response: {
        200: {
          description: 'The catalog as the authority now holds it.',
          type: 'object',
          additionalProperties: false,
          required: ['resourceId', 'registered', 'deprecated'],
          properties: {
            resourceId: { type: 'string' },
            registered: { type: 'integer', description: 'Permissions in the catalog after this call.' },
            deprecated: { type: 'integer', description: 'Permissions no longer declared, kept for existing grants.' },
            catalogVersion: { type: 'integer' },
          },
          examples: [{ resourceId: 'a1c4…', registered: 27, deprecated: 0, catalogVersion: 1 }],
        },
        401: { $ref: 'Problem#', description: 'No valid administrative token was presented.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        503: { $ref: 'Problem#', description: 'No administrative credential is configured.' },
      },
    },
  }, async (request, reply) => {
    const { name } = request.params as { name: string };
    const body = request.body as {
      realm?: string;
      audience: string;
      catalogVersion?: number;
      validationMode?: ResourceRecord['validationMode'];
      permissions: Array<{ resource: string; action: string; description?: string }>;
    };

    const realmName = body.realm ?? name;
    const realm = await fastify.db
      .collection(REALM_COLLECTION)
      .findOne({ name: realmName }, { projection: { _id: 0, realmId: 1, tenantId: 1 } }) as
      { realmId: string; tenantId: string } | null;
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm', realmName));

    const outcome = await new ResourceAdminService(fastify.db).registerCatalog(realm.realmId, realm.tenantId, name, body);
    return reply.send(outcome);
  });

  /**
   * The same read `resourceCatalog.controller.ts` exposes to a signed-in principal, admin-token
   * gated instead: the ops panel has no realm session to resolve a catalog from otherwise, and its
   * own management screen needs to see what is registered before resending a changed one through
   * the PUT above.
   */
  fastify.get('/admin/resource-servers', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'listResourceServersAdmin',
      tags: ['authorization'],
      summary: 'Every resource server registered in one realm, for the ops panel',
      description: 'No applicable standard. Same read as GET /realms/:realm/resource-servers, admin-token gated.',
      security: [{ bearerAuth: [] }],
      querystring: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      response: {
        200: {
          description: 'Every resource server this realm has registered.',
          type: 'object',
          additionalProperties: false,
          required: ['resourceServers'],
          properties: { resourceServers: { type: 'array', items: resourceServerView } },
          examples: [{
            resourceServers: [{
              resourceId: 'a1c4…', name: 'orders-api', kind: 'api', audience: 'orders-api',
              catalogVersion: 2, validationMode: 'hybrid', status: 'active',
              resources: [{ resourceId: 'b2d5…', name: 'orders', actions: ['view', 'manage'], status: 'active', catalogVersion: 1 }],
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid administrative token was presented.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        503: { $ref: 'Problem#', description: 'No administrative credential is configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.query as { realm: string };
    const realm = await fastify.db
      .collection(REALM_COLLECTION)
      .findOne({ name: realmName }, { projection: { _id: 0, realmId: 1 } }) as { realmId: string } | null;
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm', realmName));

    const { resourceServers } = await new ResourceAdminService(fastify.db).list(realm.realmId, { limit: 200 });
    return reply.send({ resourceServers });
  });
}
