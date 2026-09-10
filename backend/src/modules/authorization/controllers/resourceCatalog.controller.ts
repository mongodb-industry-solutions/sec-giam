import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ResourceAdminService } from '../services/resourceAdmin.service';
import { authorityAccess, refusal } from '../services/authorityAccess';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';
import { ResourceRecord } from '../models/resource.model';

const resourceView = {
  type: 'object',
  additionalProperties: false,
  required: ['resourceId', 'name', 'actions', 'status', 'catalogVersion'],
  properties: {
    resourceId: { type: 'string' },
    name: { type: 'string' },
    displayName: { type: 'string' },
    description: { type: 'string' },
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
    displayName: { type: 'string' },
    description: { type: 'string' },
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
 * The resource-server catalog: readable by any signed-in principal, writable by one who
 * administers `permissions`.
 *
 * The write is new here. Until now the catalog was registered exclusively through
 * `PUT /admin/resource-servers/:name/permissions` (resource.controller.ts), admin-token gated and
 * meant for a resource server's own deployment; an ordinary operator with no admin token had no way
 * to declare or edit one from the console at all. Both routes now call the identical
 * `ResourceAdminService.registerCatalog`, so neither can accept something the other would refuse.
 */
export async function resourceCatalogController(fastify: FastifyInstance) {
  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /** Tier two, exactly as roles and policies: the named permission AND a role that reaches the whole realm. */
  async function administers(realmId: string, subjectId: string, resource: string, action: string) {
    const access = await authorityAccess(fastify.db, realmId, subjectId);
    if (!access.can(resource, action) || !access.realmWide) {
      return { refused: refusal(resource, action) };
    }
    return { access };
  }

  function audit(realm: { realmId: string; tenantId: string }, action: string, subjectId: string, detail: Record<string, unknown>) {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action,
      outcome: 'success',
      subjectId,
      detail,
    });
  }

  fastify.get('/realms/:realm/resource-servers', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listResourceServers',
      tags: ['authorization'],
      summary: 'Every resource server registered in this realm',
      description:
        'No applicable standard. What `PUT /admin/resource-servers/:name/permissions` (or its '
        + 'RBAC-gated equivalent below) has registered: each application, tool or MCP server that '
        + 'declared enforcement points, and the resources and actions each one currently offers. '
        + 'Readable by any authenticated principal, the same reasoning `/permissions` already '
        + 'applies: this is the authorization MODEL, not personal data or a secret, and it exists to '
        + 'be looked up rather than guarded.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Case-insensitive match on name or audience.' },
          status: { type: 'string', enum: ['active', 'deprecated', 'withdrawn'] },
          skip: { type: 'integer', default: 0 },
          limit: { type: 'integer', default: 20, maximum: 200 },
        },
      },
      response: {
        200: {
          description: 'The resource servers this realm has registered.',
          type: 'object',
          additionalProperties: false,
          required: ['resourceServers', 'total'],
          properties: {
            resourceServers: { type: 'array', items: resourceServerView },
            total: { type: 'integer' },
          },
          examples: [{
            resourceServers: [{
              resourceId: 'a1c4…', name: 'orders-api', kind: 'api', audience: 'orders-api',
              catalogVersion: 3, validationMode: 'hybrid', status: 'active',
              registeredAt: '2026-01-01T00:00:00.000Z',
              resources: [{ resourceId: 'b2d5…', name: 'orders', actions: ['view', 'manage'], status: 'active', catalogVersion: 1 }],
            }],
            total: 1,
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const { q, status, skip, limit } = request.query as {
      q?: string; status?: ResourceRecord['status']; skip?: number; limit?: number;
    };
    return reply.send(await new ResourceAdminService(fastify.db).list(realm.realmId, { q, status, skip, limit }));
  });

  /**
   * Declares or replaces one resource server's catalog, from the ordinary console.
   *
   * `permissions:manage` rather than a narrower, per-server permission: the catalog is realm-wide
   * vocabulary, the same reasoning that keeps `/permissions` itself gated no more narrowly than
   * "administers this realm's authorization model at all" (`policy.controller.ts`'s own `policies`/
   * `roles` tiers follow the identical shape).
   */
  fastify.put('/realms/:realm/resource-servers/:name/permissions', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'registerResourceServer',
      tags: ['authorization'],
      summary: 'Declare a resource server\'s catalog, from the console',
      description:
        'No applicable standard. Identical to `PUT /admin/resource-servers/:name/permissions`, '
        + 'reached by a signed-in operator instead of an admin token: both call the same '
        + '`ResourceAdminService.registerCatalog`. Idempotent and versioned: registering the same '
        + 'catalog twice is one registration, and a permission that disappears from the declared set '
        + 'is marked withdrawn rather than deleted, because a role may already grant it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'name'],
        properties: { realm: { type: 'string', examples: ['acme'] }, name: { type: 'string', examples: ['orders-api'] } },
      },
      body: {
        type: 'object',
        required: ['audience', 'permissions'],
        additionalProperties: false,
        properties: {
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
          required: ['resourceId', 'registered', 'deprecated', 'catalogVersion'],
          properties: {
            resourceId: { type: 'string' },
            registered: { type: 'integer', description: 'Permissions in the catalog after this call.' },
            deprecated: { type: 'integer', description: 'Permissions no longer declared, kept for existing grants.' },
            catalogVersion: { type: 'integer' },
          },
          examples: [{ resourceId: 'a1c4…', registered: 27, deprecated: 0, catalogVersion: 1 }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm\'s permissions.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, name } = request.params as { realm: string; name: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'permissions', 'manage');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const body = request.body as {
      audience: string;
      catalogVersion?: number;
      validationMode?: ResourceRecord['validationMode'];
      permissions: Array<{ resource: string; action: string; description?: string }>;
    };
    const outcome = await new ResourceAdminService(fastify.db).registerCatalog(realm.realmId, realm.tenantId, name, body, caller.subjectId);

    audit(realm, 'authorization.resource-server.registered', caller.subjectId, {
      name, resourceId: outcome.resourceId, registered: outcome.registered, deprecated: outcome.deprecated,
    });
    return reply.send(outcome);
  });
}
