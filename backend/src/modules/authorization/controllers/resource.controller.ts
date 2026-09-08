import { FastifyInstance } from 'fastify';
import { v5 as uuidv5 } from 'uuid';
import { RESOURCE_COLLECTION, REALM_COLLECTION } from '../../../shared/models/collections';
import { newMeta, touchMeta, DEFAULT_TENANT_ID } from '../../../shared/models/base.model';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { problem } from '../../../shared/models/problem';
import { ResourceRecord } from '../models/resource.model';

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

    const resourceId = uuidv5(`resource-server:${realm.realmId}:${name}`, AUTHORIZATION_NAMESPACE);
    const servers = fastify.db.collection<ResourceRecord>(RESOURCE_COLLECTION);

    const existing = await servers.findOne({ resourceId });
    // A NUMBER now, not a string: it is compared and incremented, and '10' < '9' as a string is the
    // kind of ordering bug that only shows up on the tenth deploy.
    const version = Number(body.catalogVersion ?? 1);
    if (existing) {
      await servers.updateOne({ resourceId }, {
        $set: {
          name,
          audience: body.audience,
          catalogVersion: version,
          ...(body.validationMode ? { validationMode: body.validationMode } : {}),
          meta: touchMeta(existing.meta),
        },
      });
    } else {
      await servers.insertOne({
        realmId: realm.realmId,
        tenantId: realm.tenantId ?? DEFAULT_TENANT_ID,
        resourceId,
        name,
        audience: body.audience,
        // An API is one kind of resource among several. A tool and a Model Context Protocol server
        // are the others, and they go through the same decision function.
        kind: 'api',
        catalogVersion: version,
        actions: [],
        status: 'active',
        validationMode: body.validationMode ?? 'hybrid',
        registeredAt: new Date().toISOString(),
        meta: newMeta('Resource'),
      });
    }

    /**
     * The catalog is replaced as a BLOCK, per resource type, and the version is bumped.
     *
     * P5.2. Row by row edits were how a catalog drifted: a permission removed from the application
     * but left in the database looked exactly like one that still worked, and reviving it needed a
     * `deprecated` flag to be flipped back. Declaring the whole set means the database says what the
     * application says, and nothing else.
     *
     * Each resource TYPE the application declares becomes a resource of its own, parented to the
     * API. That is what lets a permission stay the single string `type:action` while the audience
     * still knows which types it enforces.
     */
    const actionsByType = new Map<string, Set<string>>();
    for (const permission of body.permissions) {
      const held = actionsByType.get(permission.resource) ?? new Set<string>();
      held.add(permission.action);
      actionsByType.set(permission.resource, held);
    }

    let registered = 0;
    for (const [type, actions] of actionsByType) {
      const childId = uuidv5(`resource:${realm.realmId}:${name}:${type}`, AUTHORIZATION_NAMESPACE);
      const declaredActions = [...actions].sort();
      const child = await servers.findOne({ resourceId: childId });
      if (child) {
        await servers.updateOne({ resourceId: childId }, {
          $set: {
            name: type,
            actions: declaredActions,
            // Bumped whenever the set changes, so drift is visible rather than silent.
            catalogVersion: JSON.stringify(child.actions ?? []) === JSON.stringify(declaredActions)
              ? child.catalogVersion
              : child.catalogVersion + 1,
            status: 'active',
            meta: touchMeta(child.meta),
          },
        });
      } else {
        await servers.insertOne({
          realmId: realm.realmId,
          tenantId: realm.tenantId ?? DEFAULT_TENANT_ID,
          resourceId: childId,
          name: type,
          // An object the API protects, reached through it rather than addressed by an audience of
          // its own.
          kind: 'object',
          parentResourceId: resourceId,
          actions: declaredActions,
          catalogVersion: 1,
          status: 'active',
          registeredAt: new Date().toISOString(),
          meta: newMeta('Resource'),
        });
      }
      registered += declaredActions.length;
    }

    // A type the application no longer declares at all. Marked withdrawn, never deleted: a role may
    // still grant something over it, and removing the resource would leave that grant referring to
    // nothing with no way to find out what it once meant.
    const children = await servers
      .find({ realmId: realm.realmId, parentResourceId: resourceId }, { projection: { _id: 0 } })
      .toArray();
    let withdrawn = 0;
    for (const child of children) {
      if (actionsByType.has(child.name)) continue;
      if (child.status === 'withdrawn') continue;
      await servers.updateOne({ resourceId: child.resourceId }, { $set: { status: 'withdrawn' } });
      withdrawn += 1;
    }

    return reply.send({
      resourceId,
      registered,
      deprecated: withdrawn,
      catalogVersion: version,
    });
  });
}
