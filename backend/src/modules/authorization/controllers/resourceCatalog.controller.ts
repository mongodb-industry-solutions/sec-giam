import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ResourceAdminService } from '../services/resourceAdmin.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

const resourceView = {
  type: 'object',
  additionalProperties: false,
  required: ['resourceId', 'name', 'actions', 'status', 'catalogVersion'],
  properties: {
    resourceId: { type: 'string' },
    name: { type: 'string' },
    actions: { type: 'array', items: { type: 'string' } },
    status: { type: 'string', enum: ['active', 'deprecated', 'withdrawn'] },
    catalogVersion: { type: 'integer' },
  },
} as const;

/**
 * Shared with `resource.controller.ts`'s own admin read of the same catalog: one shape for both,
 * so an added field cannot land on one response and be forgotten on the other.
 */
export const resourceServerView = {
  type: 'object',
  additionalProperties: false,
  required: ['resourceId', 'name', 'kind', 'catalogVersion', 'status', 'resources'],
  properties: {
    resourceId: { type: 'string' },
    name: { type: 'string' },
    kind: { type: 'string', enum: ['api', 'tool', 'mcp_server', 'object'] },
    audience: { type: 'string' },
    catalogVersion: { type: 'integer' },
    validationMode: { type: 'string', enum: ['local-jwks', 'introspection', 'hybrid'] },
    status: { type: 'string', enum: ['active', 'deprecated', 'withdrawn'] },
    registeredAt: { type: 'string' },
    resources: { type: 'array', items: resourceView },
  },
} as const;

/**
 * The resource-server catalog, read back. Registered exclusively through
 * `PUT /admin/resource-servers/:name/permissions` (resource.controller.ts); this is the ordinary
 * console's only way to see it, since that endpoint is admin-token gated and deployment-wide, not a
 * realm-scoped read a signed-in principal can reach.
 */
export async function resourceCatalogController(fastify: FastifyInstance) {
  fastify.get('/realms/:realm/resource-servers', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listResourceServers',
      tags: ['authorization'],
      summary: 'Every resource server registered in this realm',
      description:
        'No applicable standard. What `PUT /admin/resource-servers/:name/permissions` has '
        + 'registered: each application, tool or MCP server that declared enforcement points, and '
        + 'the resources and actions each one currently offers. Readable by any authenticated '
        + 'principal, the same reasoning `/permissions` already applies: this is the authorization '
        + 'MODEL, not personal data or a secret, and it exists to be looked up rather than guarded.',
      security: [{ bearerAuth: [] }],
      params: {
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
              catalogVersion: 3, validationMode: 'hybrid', status: 'active',
              registeredAt: '2026-01-01T00:00:00.000Z',
              resources: [{ resourceId: 'b2d5…', name: 'orders', actions: ['view', 'manage'], status: 'active', catalogVersion: 1 }],
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await new RealmService(fastify.db).byName((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    return reply.send({ resourceServers: await new ResourceAdminService(fastify.db).list(realm.realmId) });
  });
}
