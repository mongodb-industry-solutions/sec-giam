import { FastifyInstance } from 'fastify';
import { v5 as uuidv5 } from 'uuid';
import {
  RESOURCE_SERVER_COLLECTION, PERMISSION_COLLECTION, REALM_COLLECTION,
} from '../../../shared/models/collections';
import { ResourceServerRecord, PermissionRecord } from '../models/authorization.model';
import { newMeta, touchMeta, DEFAULT_TENANT_ID } from '../../../shared/models/base.model';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { problem } from '../../../shared/models/problem';

// The same namespace the seeders use, so a catalog registered at boot and one seeded resolve to one
// record rather than two that look alike.
const AUTHORIZATION_NAMESPACE = 'a1c4e7b2-5d9f-4a3c-8e6b-2f7d1c9a4b83';

/**
 * Where a protected application declares what it enforces.
 *
 * The direction is the whole arrangement: the application ships its enforcement points in its own
 * code and PUTs them here, because only the code containing a guard can say the permission exists.
 * The authority then decides who holds them. Neither side can invent the other's half, and an
 * application that tried to grant itself something would be writing to a collection it cannot reach.
 *
 * Idempotent by construction: the same catalog registered twice is one registration. A permission
 * that disappears from a catalog is marked DEPRECATED rather than deleted, because grants already
 * reference it and deleting it would leave those grants unexplainable.
 */
export async function resourceServerController(fastify: FastifyInstance) {
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
          permissionCatalogVersion: { type: 'string', examples: ['3'] },
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
          required: ['resourceServerId', 'registered', 'deprecated'],
          properties: {
            resourceServerId: { type: 'string' },
            registered: { type: 'integer', description: 'Permissions in the catalog after this call.' },
            deprecated: { type: 'integer', description: 'Permissions no longer declared, kept for existing grants.' },
            permissionCatalogVersion: { type: 'string' },
          },
          examples: [{ resourceServerId: 'a1c4…', registered: 27, deprecated: 0, permissionCatalogVersion: '1' }],
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
      permissionCatalogVersion?: string;
      validationMode?: ResourceServerRecord['validationMode'];
      permissions: Array<{ resource: string; action: string; description?: string }>;
    };

    const realmName = body.realm ?? name;
    const realm = await fastify.db
      .collection(REALM_COLLECTION)
      .findOne({ name: realmName }, { projection: { _id: 0, realmId: 1, tenantId: 1 } }) as
      { realmId: string; tenantId: string } | null;
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm', realmName));

    const resourceServerId = uuidv5(`resource-server:${realm.realmId}:${name}`, AUTHORIZATION_NAMESPACE);
    const servers = fastify.db.collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION);
    const permissions = fastify.db.collection<PermissionRecord>(PERMISSION_COLLECTION);

    const existing = await servers.findOne({ resourceServerId });
    const version = body.permissionCatalogVersion ?? '1';
    if (existing) {
      await servers.updateOne({ resourceServerId }, {
        $set: {
          name,
          audience: body.audience,
          permissionCatalogVersion: version,
          ...(body.validationMode ? { validationMode: body.validationMode } : {}),
          meta: touchMeta(existing.meta),
        },
      });
    } else {
      await servers.insertOne({
        realmId: realm.realmId,
        tenantId: realm.tenantId ?? DEFAULT_TENANT_ID,
        resourceServerId,
        name,
        audience: body.audience,
        permissionCatalogVersion: version,
        validationMode: body.validationMode ?? 'hybrid',
        registeredAt: new Date().toISOString(),
        meta: newMeta('ResourceServer'),
      });
    }

    const declared = new Set<string>();
    for (const permission of body.permissions) {
      const key = `${permission.resource}:${permission.action}`;
      declared.add(key);
      const permissionId = uuidv5(
        `permission:${resourceServerId}:${permission.resource}:${permission.action}`,
        AUTHORIZATION_NAMESPACE,
      );
      await permissions.updateOne(
        { permissionId },
        {
          $set: {
            resourceServerId,
            resource: permission.resource,
            action: permission.action,
            description: permission.description ?? `${permission.action} on ${permission.resource}`,
            // Re-declaring revives one that had been retired, so an application that removed a guard
            // and put it back does not need anyone to intervene.
            deprecated: false,
          },
          $setOnInsert: {
            permissionId,
            realmId: realm.realmId,
            tenantId: realm.tenantId ?? DEFAULT_TENANT_ID,
            meta: newMeta('Permission'),
          },
        },
        { upsert: true },
      );
    }

    // Anything the application no longer declares. Marked, never removed: a role may still grant it,
    // and deleting the catalog row would leave that grant referring to nothing.
    const held = await permissions.find({ resourceServerId }, { projection: { _id: 0 } }).toArray();
    let deprecated = 0;
    for (const permission of held) {
      if (declared.has(`${permission.resource}:${permission.action}`)) continue;
      await permissions.updateOne({ permissionId: permission.permissionId }, { $set: { deprecated: true } });
      deprecated += 1;
    }

    return reply.send({
      resourceServerId,
      registered: declared.size,
      deprecated,
      permissionCatalogVersion: version,
    });
  });
}
