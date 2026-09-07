import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { RoleAdminService, isRoleRefusal } from '../services/roleAdmin.service';
import { authorityAccess, refusal, AUTHORITY_RESOURCE_SERVER } from '../services/authorityAccess';
import { DecisionService } from '../services/decision.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

/**
 * Roles, what they grant, and who holds them.
 *
 * Administering a realm, so every operation here is tier two: an ordinary registered user reaches
 * their own account and nothing on this surface. That is decided by the role's own `scopeKind`
 * rather than by a second mechanism, and it is checked HERE rather than by the console: a screen
 * hidden in a navigation list is a presentation choice, and this is the access control.
 *
 * The permissions are resolved against the authority's own resource server, so an access token
 * issued for a business application never carries authority over identity by accident.
 */
export async function roleController(fastify: FastifyInstance) {
  const base = '/realms/:realm/roles';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const roleParams = {
    type: 'object',
    required: ['realm', 'roleId'],
    properties: { realm: { type: 'string' }, roleId: { type: 'string' } },
  } as const;

  const permissionView = {
    type: 'object',
    additionalProperties: false,
    required: ['resource', 'action', 'resourceServer', 'via', 'inherited', 'unenforced'],
    properties: {
      resource: { type: 'string' },
      action: { type: 'string' },
      resourceServer: { type: 'string', description: 'The application that declared this enforcement point.' },
      via: { type: 'string', description: 'The role it actually comes from, which differs when it is inherited.' },
      inherited: { type: 'boolean' },
      unenforced: { type: 'boolean', description: 'No resource server declares it, so nothing checks it.' },
    },
  } as const;

  const roleSummary = {
    type: 'object',
    additionalProperties: false,
    required: ['roleId', 'name', 'displayName', 'scopeKind', 'builtin'],
    properties: {
      roleId: { type: 'string' },
      name: { type: 'string' },
      displayName: { type: 'string' },
      description: { type: 'string' },
      scopeKind: { type: 'string', enum: ['self', 'all'], description: '`self` reaches only the holder\'s own records; `all` is realm wide.' },
      builtin: { type: 'boolean' },
      parentRoleIds: { type: 'array', items: { type: 'string' } },
      ownPermissionCount: { type: 'integer' },
      effectivePermissionCount: { type: 'integer' },
      assignmentCount: { type: 'integer' },
    },
    examples: [{
      roleId: 'a3f1e0c2-77d4-4a11-9c2e-2b6f0a51d8e4',
      name: 'realm_administrator',
      displayName: 'Realm administrator',
      description: 'Administers the identities, roles, keys and sessions of one realm.',
      scopeKind: 'all',
      builtin: true,
      parentRoleIds: [],
      ownPermissionCount: 14,
      effectivePermissionCount: 14,
      assignmentCount: 1,
    }],
  } as const;

  const roleDetail = {
    type: 'object',
    additionalProperties: false,
    required: ['roleId', 'name', 'displayName', 'scopeKind', 'builtin', 'ownPermissions', 'effectivePermissions'],
    properties: {
      ...roleSummary.properties,
      parents: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: { roleId: { type: 'string' }, name: { type: 'string' }, displayName: { type: 'string' } },
        },
      },
      ownPermissions: { type: 'array', items: permissionView },
      effectivePermissions: {
        type: 'array',
        items: permissionView,
        description: 'What the role grants once composition through its parents is resolved.',
      },
      sodRationale: { type: 'string' },
      denialRationale: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: { resource: { type: 'string' }, action: { type: 'string' }, reason: { type: 'string' } },
        },
      },
      created: { type: 'string' },
      lastModified: { type: 'string' },
    },
    examples: [{
      ...roleSummary.examples[0],
      parents: [],
      ownPermissions: [{ resource: 'roles', action: 'view', resourceServer: 'authority', via: 'realm_administrator', inherited: false, unenforced: false }],
      effectivePermissions: [{ resource: 'roles', action: 'view', resourceServer: 'authority', via: 'realm_administrator', inherited: false, unenforced: false }],
    }],
  } as const;

  const assignmentView = {
    type: 'object',
    additionalProperties: false,
    required: ['subjectId', 'roleId', 'grantedAt', 'live'],
    properties: {
      subjectId: { type: 'string' },
      /**
       * The person behind the subject id.
       *
       * DECLARED, or it is stripped: `additionalProperties: false` means a field the schema does
       * not name never reaches the caller, however carefully the service resolved it. The service
       * was returning this and the screen was still showing an identifier.
       */
      userName: { type: 'string' },
      roleId: { type: 'string' },
      grantedAt: { type: 'string' },
      grantedBy: { type: 'string' },
      expiresAt: { type: 'string' },
      ephemeral: { type: 'boolean' },
      justification: { type: 'string' },
      live: { type: 'boolean', description: 'False once an expiry has passed.' },
    },
    examples: [{
      subjectId: 'a1000070-0000-4000-8000-000000000070',
      userName: 'Alex Rivera',
      roleId: 'a3f1e0c2-77d4-4a11-9c2e-2b6f0a51d8e4',
      grantedAt: '2026-08-30T09:12:00.000Z',
      live: true,
    }],
  } as const;

  const permissionPairs = {
    type: 'array',
    items: {
      type: 'object',
      required: ['resource', 'action'],
      additionalProperties: false,
      properties: { resource: { type: 'string' }, action: { type: 'string' } },
    },
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /**
   * Tier two, or nothing.
   *
   * Both halves are required: the named permission, and a role whose scope reaches beyond the
   * holder's own records. A `self` scoped role holding `roles:view` would be a contradiction, and
   * resolving it in favour of access is how an ordinary user ends up reading the permission matrix.
   */
  async function administers(realmId: string, subjectId: string, resource: string, action: string) {
    const access = await authorityAccess(fastify.db, realmId, subjectId);
    if (!access.can(resource, action) || !access.realmWide) {
      return { refused: refusal(resource, action) };
    }
    return { access };
  }

  /**
   * One authorization change, recorded, whichever way it went.
   *
   * The outcome is a parameter rather than a constant because a REFUSED attempt to grant a role is
   * the entry an auditor most needs: somebody trying to widen their own authority looks exactly like
   * nothing at all in a trail that only holds what succeeded.
   */
  function audit(
    realm: { realmId: string; tenantId: string },
    action: string,
    subjectId: string,
    detail: Record<string, unknown>,
    outcome: 'success' | 'failure' = 'success',
    cause?: string,
  ) {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action,
      outcome,
      subjectId,
      ...(cause ? { cause } : {}),
      detail,
    });
  }

  /**
   * The refusal a gate produced, recorded and returned.
   *
   * Every privileged route here goes through it, so the trail cannot have a route where the refusal
   * was left out because that one was added later.
   */
  function refused(
    realm: { realmId: string; tenantId: string },
    action: string,
    subjectId: string,
    reason: string | undefined,
    detail: Record<string, unknown> = {},
  ) {
    audit(realm, action, subjectId, detail, 'failure', 'not_permitted');
    return problem(403, 'Not permitted', reason);
  }

  fastify.get('/realms/:realm/me/permissions', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'myPermissions',
      tags: ['authorization'],
      summary: 'What this principal may do to the authority\'s own objects, resolved fresh',
      description:
        'No applicable standard; console UI gating. The access token carries roles rather than '
        + 'entitlements by default (P9), so a screen deciding what to show cannot read the token '
        + 'alone without the answer being wrong for every default login. This is the same read the '
        + 'authority does to decide, not a claim the caller could be stale about: a role withdrawn a '
        + 'moment ago is withdrawn here too. It answers only for the CALLER, so no permission beyond '
        + '"read your own" gates it.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The caller\'s own effective permissions on the authority.',
          type: 'object',
          additionalProperties: false,
          required: ['permissions', 'roles', 'scopeKind'],
          properties: {
            permissions: { type: 'array', items: { type: 'string' }, description: '`resource:action` strings.' },
            roles: { type: 'array', items: { type: 'string' } },
            scopeKind: { type: 'string', enum: ['self', 'all'] },
          },
          examples: [{ permissions: ['sessions:view', 'sessions:manage'], roles: ['realm_administrator'], scopeKind: 'all' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const decision = await new DecisionService(fastify.db)
      .effectivePermissions(realm.realmId, caller.subjectId, AUTHORITY_RESOURCE_SERVER);
    return reply.send({ permissions: decision.permissions, roles: decision.roles, scopeKind: decision.scopeKind });
  });

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listRoles',
      tags: ['authorization'],
      summary: 'The roles this realm defines',
      description:
        'No applicable standard. Each row carries what the role grants directly and what it grants '
        + 'once composition through its parents is resolved, because the two differ and only one of '
        + 'them is what a token will actually carry. The assignment count is here rather than a '
        + 'screen away: a role nobody holds and a role everybody holds are different objects.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Case-insensitive match on name, display name or description.' },
          skip: { type: 'integer', default: 0 },
          limit: { type: 'integer', default: 20, maximum: 200 },
        },
      },
      response: {
        200: {
          description: 'The roles defined in this realm.',
          type: 'object',
          additionalProperties: false,
          required: ['roles', 'total'],
          properties: { roles: { type: 'array', items: roleSummary }, total: { type: 'integer' } },
          examples: [{ roles: [roleSummary.examples[0]], total: 1 }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'roles', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const { q, skip, limit } = request.query as { q?: string; skip?: number; limit?: number };
    return reply.send(await new RoleAdminService(fastify.db).list(realm.realmId, { q, skip, limit }));
  });

  // Its own path rather than a child of /roles: it is the resource servers' catalog, not a role's,
  // and a static segment sitting beside `/roles/{roleId}` reads as ambiguous in the contract.
  fastify.get('/realms/:realm/permissions', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listPermissionCatalog',
      tags: ['authorization'],
      summary: 'Every permission a role could be given',
      description:
        'No applicable standard. The union of the enforcement points the realm\'s resource servers '
        + 'have registered. It is a separate read from the roles themselves because a role can only '
        + 'ever grant what an application declared it enforces, and building one against a list of '
        + 'free text would produce permissions nothing checks.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The declared enforcement points.',
          type: 'object',
          additionalProperties: false,
          required: ['permissions', 'roles', 'catalogVersion'],
          properties: {
            /**
             * P9.5. The role catalog, with its version, so a resource server can CACHE it.
             *
             * A token carries roles by default, which means a resource server that enforces
             * permissions has to expand them. It either calls the decision endpoint per request or
             * caches this and expands locally, and caching needs a version to know when to stop.
             *
             * Derived from the resources rather than stored: the version is the highest
             * catalogVersion any resource declares, so it moves whenever a catalog does and there
             * is no second number to keep in step.
             */
            catalogVersion: { type: 'integer', description: 'Bumps whenever any resource catalog changes. Cache against this.' },
            roles: {
              type: 'array',
              description: 'Each role with the full permission strings it grants, parents resolved.',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['name', 'permissions'],
                properties: {
                  name: { type: 'string' },
                  permissions: { type: 'array', items: { type: 'string' } },
                },
              },
            },
            permissions: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['permission', 'resource', 'action', 'resourceServer'],
                properties: {
                  permission: { type: 'string', description: 'The full string, `resource:action`. The one spelling a role, a policy and a token all use.' },
                  resource: { type: 'string' },
                  action: { type: 'string' },
                  description: { type: 'string' },
                  resourceServer: { type: 'string' },
                },
              },
            },
          },
          // `catalogVersion` belongs to the RESPONSE, not to each role. The example carried it inside
          // the role item too, where the item schema does not declare it and refuses extras.
          examples: [{
            permissions: [{
              permission: 'roles:manage', resource: 'roles', action: 'manage',
              description: 'the role catalogue', resourceServer: 'authority',
            }],
            roles: [{ name: 'realm_administrator', permissions: ['roles:manage'] }],
            catalogVersion: 3,
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    /**
     * Readable by ANY authenticated principal, and deliberately not narrowed.
     *
     * Two wrong answers were tried first. Requiring `permissions:view` refused it to almost every
     * caller, and a resource server must expand the roles in a presented token on every request, so
     * an analyst or a card officer resolved nothing and was then refused every guarded route.
     * Narrowing the response to the caller's own roles fixed that and broke something worse: this
     * endpoint exists to be CACHED, which is why it carries a version, and a response that depends
     * on who asked means the first caller's narrow view is served to everybody afterwards.
     *
     * So it is the whole catalog, to anybody holding a valid token for this realm. What it contains
     * is role names and permission names: the authorization MODEL, with no personal data, no
     * secret, and nothing about who holds what. That is the same category of thing as a discovery
     * document, and it is what "published" was always meant to mean.
     */
    return reply.send(await new RoleAdminService(fastify.db).publishedCatalog(realm.realmId));
  });

  fastify.get(`${base}/:roleId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getRole',
      tags: ['authorization'],
      summary: 'One role, with everything it inherits',
      description:
        'No applicable standard. Both permission sets are returned: what the role states itself and '
        + 'what it grants once its parents are resolved. A reader shown only the second cannot tell '
        + 'which line to edit, and one shown only the first does not know what the role actually '
        + 'does. Any recorded separation-of-duties reasoning travels with it.',
      security: [{ bearerAuth: [] }],
      params: roleParams,
      response: {
        200: { ...roleDetail, description: 'The role.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such role in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, roleId } = request.params as { realm: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'roles', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const detail = await new RoleAdminService(fastify.db).detail(realm.realmId, roleId);
    if (!detail) return reply.status(404).send(problem(404, 'No such role'));
    return reply.send(detail);
  });

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'createRole',
      tags: ['authorization'],
      summary: 'Define a role',
      description:
        'No applicable standard. Every permission named has to be one a resource server already '
        + 'registered, and one that is not is refused rather than stored: the authority grants what '
        + 'applications say they enforce, and a role granting something nothing checks looks '
        + 'identical to one that works.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['name'],
        additionalProperties: false,
        properties: {
          name: { type: 'string', minLength: 1, pattern: '^[a-zA-Z0-9._-]+$' },
          displayName: { type: 'string' },
          description: { type: 'string' },
          scopeKind: { type: 'string', enum: ['self', 'all'], default: 'self' },
          permissions: permissionPairs,
          parentRoleIds: { type: 'array', items: { type: 'string' } },
          sodRationale: { type: 'string' },
        },
      },
      response: {
        201: { ...roleDetail, description: 'The role as defined.' },
        400: { $ref: 'Problem#', description: 'A permission or a parent that does not exist was named.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That name is taken, or the composition would loop.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'roles', 'manage');
    if ('refused' in gate) return reply.status(403).send(refused(realm, 'authorization.role.created', caller.subjectId, gate.refused, { name: (request.body as { name?: string })?.name }));

    const outcome = await new RoleAdminService(fastify.db)
      .create(realm.realmId, realm.tenantId, request.body as { name: string });
    if (isRoleRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.role.created', caller.subjectId, { roleId: outcome.roleId, name: outcome.name });
    return reply.status(201).send(outcome);
  });

  fastify.patch(`${base}/:roleId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'updateRole',
      tags: ['authorization'],
      summary: 'Change what a role grants',
      description:
        'No applicable standard. Partial: only the fields present are changed. The permission list '
        + 'is replaced rather than merged, because a role is a statement of what it grants and '
        + 'merging would make removing a permission impossible through this route. Built-in roles '
        + 'can be edited; setup recreates the fields it owns on the next run, which is stated here '
        + 'rather than discovered.',
      security: [{ bearerAuth: [] }],
      params: roleParams,
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          displayName: { type: 'string' },
          description: { type: 'string' },
          scopeKind: { type: 'string', enum: ['self', 'all'] },
          permissions: permissionPairs,
          parentRoleIds: { type: 'array', items: { type: 'string' } },
          sodRationale: { type: 'string' },
        },
      },
      response: {
        200: { ...roleDetail, description: 'The role, as it now stands.' },
        400: { $ref: 'Problem#', description: 'A permission or a parent that does not exist was named.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such role in this realm.' },
        409: { $ref: 'Problem#', description: 'The composition would loop.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, roleId } = request.params as { realm: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'roles', 'manage');
    if ('refused' in gate) return reply.status(403).send(refused(realm, 'authorization.role.updated', caller.subjectId, gate.refused, { roleId }));

    const outcome = await new RoleAdminService(fastify.db).update(realm.realmId, roleId, request.body as object);
    if (outcome === null) return reply.status(404).send(problem(404, 'No such role'));
    if (isRoleRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.role.updated', caller.subjectId, { roleId, fields: Object.keys(request.body ?? {}) });
    return reply.send(outcome);
  });

  fastify.delete(`${base}/:roleId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'deleteRole',
      tags: ['authorization'],
      summary: 'Remove a role',
      description:
        'No applicable standard. Refused while anything still depends on it, and the refusal names '
        + 'how many assignments or child roles do. Cascading would take authority away from everyone '
        + 'holding it in one unwatched moment, which is a decision nobody made.',
      security: [{ bearerAuth: [] }],
      params: roleParams,
      response: {
        200: {
          description: 'Removed.',
          type: 'object',
          additionalProperties: false,
          required: ['removed', 'roleId'],
          properties: { removed: { type: 'boolean' }, roleId: { type: 'string' } },
          examples: [{ removed: true, roleId: 'a3f1e0c2-77d4-4a11-9c2e-2b6f0a51d8e4' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such role in this realm.' },
        409: { $ref: 'Problem#', description: 'Still assigned, composed into another role, or built in.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, roleId } = request.params as { realm: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'roles', 'manage');
    if ('refused' in gate) return reply.status(403).send(refused(realm, 'authorization.role.removed', caller.subjectId, gate.refused, { roleId }));

    const outcome = await new RoleAdminService(fastify.db).remove(realm.realmId, roleId);
    if (outcome === null) return reply.status(404).send(problem(404, 'No such role'));
    if (isRoleRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.role.removed', caller.subjectId, { roleId });
    return reply.send({ removed: true, roleId });
  });

  fastify.get(`${base}/:roleId/assignments`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listRoleAssignments',
      tags: ['authorization'],
      summary: 'Who holds this role',
      description:
        'No applicable standard. Lapsed assignments are listed alongside live ones, because "who '
        + 'used to hold this, and until when" is the question asked after something goes wrong, and '
        + 'a list that quietly drops them cannot answer it.',
      security: [{ bearerAuth: [] }],
      params: roleParams,
      response: {
        200: {
          description: 'Everyone who holds or held this role.',
          type: 'object',
          additionalProperties: false,
          required: ['assignments'],
          properties: { assignments: { type: 'array', items: assignmentView } },
          examples: [{ assignments: [assignmentView.examples[0]] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such role in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, roleId } = request.params as { realm: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'assignments', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const service = new RoleAdminService(fastify.db);
    const role = await service.detail(realm.realmId, roleId);
    if (!role) return reply.status(404).send(problem(404, 'No such role'));
    return reply.send({ assignments: await service.assignmentsFor(realm.realmId, roleId) });
  });

  fastify.post(`${base}/:roleId/assignments`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'grantRoleAssignment',
      tags: ['authorization'],
      summary: 'Give a principal this role',
      description:
        'No applicable standard. An assignment with an expiry is a time-bound elevation and is '
        + 'marked as one, so the expiry sweep can never touch a standing grant. The same record type '
        + 'expresses both, which is what makes an elevation listable and revocable in the way a '
        + 'stateless capability token is not.',
      security: [{ bearerAuth: [] }],
      params: roleParams,
      body: {
        type: 'object',
        required: ['subjectId'],
        additionalProperties: false,
        properties: {
          subjectId: { type: 'string', minLength: 1 },
          expiresAt: { type: 'string', format: 'date-time', description: 'Makes this an elevation rather than a standing grant.' },
          justification: { type: 'string' },
        },
      },
      response: {
        201: { ...assignmentView, description: 'The assignment.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such role in this realm.' },
        409: { $ref: 'Problem#', description: 'That principal already holds this role.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, roleId } = request.params as { realm: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'assignments', 'manage');
    if ('refused' in gate) return reply.status(403).send(refused(realm, 'authorization.assignment.granted', caller.subjectId, gate.refused, { roleId }));

    const body = request.body as { subjectId: string; expiresAt?: string; justification?: string };
    const outcome = await new RoleAdminService(fastify.db).grant(realm.realmId, realm.tenantId, {
      roleId,
      grantedBy: caller.subjectId,
      ...body,
    });
    if (outcome === null) return reply.status(404).send(problem(404, 'No such role'));
    if (isRoleRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.assignment.granted', caller.subjectId, {
      roleId, holder: outcome.subjectId,
    });
    return reply.status(201).send(outcome);
  });

  fastify.delete('/realms/:realm/principals/:subjectId/roles/:roleId', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'revokeRoleAssignment',
      tags: ['authorization'],
      summary: 'Take a role back from a principal',
      description:
        'No applicable standard. Removes one holding and nothing else: the role, and everyone '
        + 'else holding it, are untouched. Addressed by the subject and the role, because a role a '
        + 'subject holds lives on the subject and has no identifier of its own. It takes effect at '
        + 'the next token issued, which is why access-token lifetimes are short and why the '
        + 'irreversible operations introspect.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'subjectId', 'roleId'],
        properties: { realm: { type: 'string' }, subjectId: { type: 'string' }, roleId: { type: 'string' } },
      },
      response: {
        200: {
          description: 'Revoked.',
          type: 'object',
          additionalProperties: false,
          required: ['revoked', 'subjectId', 'roleId'],
          properties: { revoked: { type: 'boolean' }, subjectId: { type: 'string' }, roleId: { type: 'string' } },
          examples: [{ revoked: true, subjectId: 'a1000070-0000-4000-8000-000000000070', roleId: 'a3f1e0c2-77d4-4a11-9c2e-2b6f0a51d8e4' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'That principal does not hold that role in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, subjectId, roleId } = request.params as
      { realm: string; subjectId: string; roleId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'assignments', 'manage');
    if ('refused' in gate) return reply.status(403).send(refused(realm, 'authorization.assignment.revoked', caller.subjectId, gate.refused, { subjectId, roleId }));

    const revoked = await new RoleAdminService(fastify.db).revoke(realm.realmId, subjectId, roleId);
    if (!revoked) return reply.status(404).send(problem(404, 'No such holding'));

    audit(realm, 'authorization.assignment.revoked', caller.subjectId, {
      holder: revoked.subjectId, roleId: revoked.roleId,
    });
    return reply.send({ revoked: true, subjectId: revoked.subjectId, roleId: revoked.roleId });
  });
}
