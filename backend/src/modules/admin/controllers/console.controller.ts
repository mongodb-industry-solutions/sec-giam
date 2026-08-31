import { FastifyInstance } from 'fastify';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { requireAuthorityCaller } from '../../../vendors/middleware/authorityAuth';
import { problem } from '../../../shared/models/problem';
import {
  REALM_COLLECTION, IDENTITY_PROVIDER_COLLECTION, IDENTITY_COLLECTION, CREDENTIAL_COLLECTION,
  CLIENT_COLLECTION, ROLE_COLLECTION, ROLE_ASSIGNMENT_COLLECTION, POLICY_COLLECTION,
  PERMISSION_COLLECTION, RESOURCE_SERVER_COLLECTION, SESSION_COLLECTION, SIGNING_KEY_COLLECTION,
  GRANT_COLLECTION,
} from '../../../shared/models/collections';

/**
 * What the operator console reads.
 *
 * Every view is an explicit entry below with an explicit projection. The tempting version of this
 * file is one route that takes a collection name and returns documents, and it is exactly wrong: the
 * first time somebody points it at `credential` or `token` it hands out secret material, and nothing
 * in the code would have objected. Naming each view and each field means a new one is a decision
 * somebody made rather than a consequence of a parameter.
 *
 * Read only. Changing a realm, a role or a client is a mutation with its own route, its own audit
 * event and its own authorisation; none of them are hidden behind a console listing.
 */

interface ConsoleView {
  collection: string;
  /** Fields returned. A field absent here cannot be reached through this surface at all. */
  projection: Record<string, 0 | 1>;
  /** Narrows a listing to one realm when asked. Absent where a record is not realm scoped. */
  realmScoped: boolean;
  sort: Record<string, 1 | -1>;
  summary: string;
  /** Why this view shows what it shows, where the answer is not obvious. */
  note?: string;
}

const VIEWS: Record<string, ConsoleView> = {
  realms: {
    collection: REALM_COLLECTION,
    projection: { _id: 0, realmId: 1, tenantId: 1, name: 1, displayName: 1, issuer: 1, enabled: 1, demoMode: 1, tokenPolicy: 1, branding: 1 },
    realmScoped: false,
    sort: { name: 1 },
    summary: 'The trust boundaries this authority serves',
  },
  providers: {
    collection: IDENTITY_PROVIDER_COLLECTION,
    projection: { _id: 0, realmId: 1, name: 1, displayName: 1, protocol: 1, enabled: 1, issuer: 1, notice: 1 },
    realmScoped: true,
    sort: { name: 1 },
    summary: 'Where a realm will accept an identity from',
    note: 'Client secrets and endpoints a provider authenticates with are deliberately not returned.',
  },
  identities: {
    collection: IDENTITY_COLLECTION,
    projection: { _id: 0, realmId: 1, subjectId: 1, userName: 1, primaryEmail: 1, name: 1, type: 1, status: 1, demoFeatured: 1, sessionEpoch: 1, accountHolderRef: 1 },
    realmScoped: true,
    sort: { userName: 1 },
    summary: 'Every principal, human and otherwise',
    note: 'No credential material of any kind, because a directory listing is not a place to learn how to authenticate as somebody.',
  },
  credentials: {
    collection: CREDENTIAL_COLLECTION,
    projection: { _id: 0, credentialId: 1, subjectId: 1, type: 1, algorithm: 1, label: 1, status: 1, assurance: 1, createdAt: 1, lastUsedAt: 1, signCount: 1 },
    realmScoped: true,
    sort: { createdAt: -1 },
    summary: 'What each principal can authenticate with',
    note: 'The hash and the public key are both withheld. An operator needs to know a credential EXISTS and what kind it is, never its material.',
  },
  clients: {
    collection: CLIENT_COLLECTION,
    projection: { _id: 0, realmId: 1, clientId: 1, clientName: 1, type: 1, status: 1, grantTypes: 1, redirectUris: 1, scope: 1, logoUri: 1, owner: 1, requirePkce: 1, backchannel: 1 },
    realmScoped: true,
    sort: { clientName: 1 },
    summary: 'The applications registered against this authority',
    note: 'The secret hash is never returned, and neither is anything that would let a reader impersonate the client.',
  },
  roles: {
    collection: ROLE_COLLECTION,
    projection: { _id: 0, realmId: 1, roleId: 1, name: 1, displayName: 1, description: 1, scopeKind: 1, permissions: 1, builtin: 1, sodRationale: 1, denialRationale: 1 },
    realmScoped: true,
    sort: { name: 1 },
    summary: 'What a role grants, and why it withholds the rest',
    note: 'The separation-of-duties rationale travels with the role: an absence with no recorded reason reads as an oversight rather than a decision.',
  },
  assignments: {
    collection: ROLE_ASSIGNMENT_COLLECTION,
    projection: { _id: 0, realmId: 1, subjectId: 1, roleId: 1, grantedAt: 1, grantedBy: 1, expiresAt: 1 },
    realmScoped: true,
    sort: { grantedAt: -1 },
    summary: 'Who holds which role',
  },
  policies: {
    collection: POLICY_COLLECTION,
    projection: { _id: 0, realmId: 1, policyId: 1, name: 1, description: 1, effect: 1, evaluator: 1, target: 1, condition: 1, enabled: 1 },
    realmScoped: true,
    sort: { name: 1 },
    summary: 'The rules evaluated beyond role membership',
  },
  permissions: {
    collection: PERMISSION_COLLECTION,
    projection: { _id: 0, realmId: 1, resourceServerId: 1, resource: 1, action: 1, description: 1 },
    realmScoped: true,
    sort: { resource: 1 },
    summary: 'Every permission a resource server has declared',
  },
  'resource-servers': {
    collection: RESOURCE_SERVER_COLLECTION,
    projection: { _id: 0, realmId: 1, resourceServerId: 1, name: 1, displayName: 1, registeredAt: 1 },
    realmScoped: true,
    sort: { name: 1 },
    summary: 'The applications that enforce this authority decisions',
  },
  sessions: {
    collection: SESSION_COLLECTION,
    projection: { _id: 0, realmId: 1, sessionId: 1, subjectId: 1, clientId: 1, status: 1, createdAt: 1, lastSeenAt: 1, expiresAt: 1, assurance: 1 },
    realmScoped: true,
    sort: { createdAt: -1 },
    summary: 'Who is currently signed in, and from which application',
  },
  grants: {
    collection: GRANT_COLLECTION,
    projection: { _id: 0, realmId: 1, grantId: 1, subjectId: 1, clientId: 1, scope: 1, status: 1, grantedAt: 1, revokedAt: 1, lastUsedAt: 1 },
    realmScoped: true,
    sort: { grantedAt: -1 },
    summary: 'What principals have authorised applications to do',
  },
  keys: {
    collection: SIGNING_KEY_COLLECTION,
    projection: { _id: 0, realmId: 1, kid: 1, instanceId: 1, provider: 1, status: 1, publishedAt: 1, leaseExpiresAt: 1, publicationExpiresAt: 1, algorithm: 1 },
    realmScoped: true,
    sort: { publishedAt: -1 },
    summary: 'The signing keys currently published, and which replica holds each',
    note: 'The private half never reaches the database, so there is nothing here to withhold. That is a property of the design rather than of this projection.',
  },
};

export async function consoleController(fastify: FastifyInstance) {
  const names = Object.keys(VIEWS);

  fastify.get('/admin/views', {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'listConsoleViews',
      tags: ['admin'],
      summary: 'What the console can read, and what each view withholds',
      description:
        'No applicable standard. The catalog the console builds itself from, so a new view appears '
        + 'without the console being changed. Each entry states what it returns and, where relevant, '
        + 'what it deliberately does not.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'The available views.',
          type: 'object',
          additionalProperties: false,
          required: ['views'],
          properties: {
            views: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  name: { type: 'string' },
                  summary: { type: 'string' },
                  note: { type: 'string' },
                  realmScoped: { type: 'boolean' },
                  canManage: { type: 'boolean' },
                  fields: { type: 'array', items: { type: 'string' } },
                },
              },
            },
          },
          examples: [{
            views: [{
              name: 'identities',
              summary: 'Every principal, human and otherwise',
              realmScoped: true,
              fields: ['subjectId', 'userName', 'status'],
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No administrative credential.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => reply.send({
    // Only what this caller may read. A catalog that advertises a view the caller's role would refuse
    // builds a console full of screens that answer 403, which reads as broken rather than as scoped.
    views: names.filter((name) => request.authorityCaller?.can(name, 'view')).map((name) => {
      const view = VIEWS[name];
      return {
        name,
        summary: view.summary,
        ...(view.note ? { note: view.note } : {}),
        realmScoped: view.realmScoped,
        fields: Object.keys(view.projection).filter((field) => field !== '_id'),
        // What the console may offer beyond reading, so it renders no control the API would refuse.
        canManage: Boolean(request.authorityCaller?.can(name, 'manage')),
      };
    }),
  }));

  fastify.get('/admin/views/:view', {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'readConsoleView',
      tags: ['admin'],
      summary: 'Read one view',
      description:
        'No applicable standard. Returns only the fields the named view declares. A field that is not '
        + 'declared cannot be reached through this surface at all, which is why there is no route '
        + 'here that takes a collection name.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['view'],
        properties: { view: { type: 'string', examples: ['identities'] } },
      },
      querystring: {
        type: 'object',
        properties: {
          realm: { type: 'string', description: 'Narrows a realm-scoped view to one realm.' },
          q: { type: 'string', description: 'Case-insensitive match across the view\'s text fields.' },
          limit: { type: 'integer', default: 100, maximum: 500 },
          skip: { type: 'integer', default: 0 },
        },
      },
      response: {
        200: {
          description: 'The matching records, and how many there are in total.',
          type: 'object',
          additionalProperties: false,
          required: ['records', 'total'],
          properties: {
            records: { type: 'array', items: { type: 'object', additionalProperties: true } },
            total: { type: 'integer' },
          },
          examples: [{ records: [{ subjectId: 'sub-4821', userName: 'ada' }], total: 1 }],
        },
        401: { $ref: 'Problem#', description: 'No administrative credential.' },
        403: { $ref: 'Problem#', description: 'The caller holds no role permitting this view.' },
        404: { $ref: 'Problem#', description: 'No such view.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { view: viewName } = request.params as { view: string };
    const view = VIEWS[viewName];
    if (!view) return reply.status(404).send(problem(404, 'No such view', `Known views: ${names.join(', ')}`));

    // Checked here rather than in a preHandler because the permission depends on which view was asked
    // for, which is not known until the parameters are read.
    if (!request.authorityCaller?.can(viewName, 'view')) {
      return reply.status(403).send(problem(403, 'Forbidden', `Your role does not permit view on ${viewName}.`));
    }

    const { realm, q, limit, skip } = request.query as { realm?: string; q?: string; limit?: number; skip?: number };
    const filter: Record<string, unknown> = {};

    if (view.realmScoped && realm) {
      const realmRecord = await fastify.db.collection(REALM_COLLECTION)
        .findOne({ name: realm }, { projection: { _id: 0, realmId: 1 } }) as { realmId?: string } | null;
      // A realm that does not exist narrows to nothing rather than to everything. Falling back to an
      // unfiltered listing on a typo is how an operator ends up reading another tenant's records.
      filter.realmId = realmRecord?.realmId ?? ' none';
    }

    if (q) {
      // Only across fields the view already returns. Searching a field it withholds would let a
      // caller confirm a value they are not allowed to read.
      const searchable = Object.keys(view.projection).filter((field) => field !== '_id');
      const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = searchable.map((field) => ({ [field]: { $regex: escaped, $options: 'i' } }));
    }

    const collection = fastify.db.collection(view.collection);
    const [records, total] = await Promise.all([
      collection
        .find(filter, { projection: view.projection })
        .sort(view.sort)
        .skip(Math.max(0, skip ?? 0))
        .limit(Math.min(limit ?? 100, 500))
        .toArray(),
      collection.countDocuments(filter),
    ]);

    return reply.send({ records, total });
  });
}
