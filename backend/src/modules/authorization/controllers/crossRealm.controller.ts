import { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { DecisionService } from '../services/decision.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';
import { ROLE_ASSIGNMENT_COLLECTION, PRINCIPAL_COLLECTION } from '../../../shared/models/collections';
import { RoleRecord, RoleAssignmentRecord, REALM_SCOPE_KIND } from '../models/authorization.model';
import { ROLE_COLLECTION } from '../../../shared/models/collections';
import { newMeta } from '../../../shared/models/base.model';

/**
 * Administering more than one realm, without a principal existing in more than one.
 *
 * Realm isolation is the property everything else here rests on: a token is minted by one realm,
 * signed with that realm's key and issued under that realm's name, and no other realm accepts it as
 * its own. Somebody who administers two realms would break that if they were given a second identity,
 * so they are not. They keep one home realm, and they hold an assignment there whose scope NAMES the
 * other realm.
 *
 * That is the whole mechanism. The token never widens; the grant is a stored record that is read
 * again on every request, listable, revocable, and impossible to hold without somebody having granted
 * it. An unscoped assignment still means the holder's own realm and nothing else, so nothing becomes
 * cross-realm by accident.
 */

/** The authority's own resource server, where permissions over these objects are registered. */
const AUTHORITY_RESOURCE_SERVER = 'authority';

export async function crossRealmController(fastify: FastifyInstance) {
  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const permissionView = {
    type: 'object',
    additionalProperties: false,
    required: ['resource', 'action'],
    properties: { resource: { type: 'string' }, action: { type: 'string' } },
  } as const;

  const administrableRealmView = {
    type: 'object',
    additionalProperties: false,
    required: ['realmId', 'name', 'displayName', 'home', 'roles', 'permissions'],
    properties: {
      realmId: { type: 'string' },
      name: { type: 'string', description: 'What a request path names this realm.' },
      displayName: { type: 'string' },
      home: { type: 'boolean', description: 'True for the realm that issues this principal\'s tokens.' },
      roles: { type: 'array', items: { type: 'string' } },
      permissions: {
        type: 'array',
        items: permissionView,
        description: 'What the caller holds IN that realm, which is usually narrower away from home.',
      },
    },
  } as const;

  const grantView = {
    type: 'object',
    additionalProperties: true,
    required: ['assignmentId', 'subjectId', 'roleId'],
    properties: {
      assignmentId: { type: 'string' },
      subjectId: { type: 'string' },
      roleId: { type: 'string' },
      roleName: { type: 'string' },
      targetRealmId: { type: 'string' },
      targetRealm: { type: 'string' },
      grantedBy: { type: 'string' },
      grantedAt: { type: 'string' },
      expiresAt: { type: 'string' },
      justification: { type: 'string' },
    },
    examples: [{
      assignmentId: 'rgrant-9f21',
      subjectId: 'sub-4821',
      roleId: 'role-security-auditor',
      roleName: 'security_auditor',
      targetRealmId: 'd1a2b3c4-0001-0001-0001-000000000009',
      targetRealm: 'partner',
      grantedBy: 'sub-1180',
      grantedAt: '2026-08-30T09:00:00.000Z',
      justification: 'Oversight of both realms during the migration.',
    }],
  } as const;

  const decisions = () => new DecisionService(fastify.db);
  const events = () => new SecurityEventService(fastify.db);
  const realms = () => new RealmService(fastify.db);
  const assignments = () => fastify.db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);

  /**
   * Everything a grant record needs spelled out for a reader.
   *
   * The stored record holds ids because that is what a decision is made against; a person reading a
   * list needs the names, and resolving them here is cheaper than making every client do it.
   */
  async function describe(record: RoleAssignmentRecord) {
    const role = await fastify.db.collection<RoleRecord>(ROLE_COLLECTION)
      .findOne({ roleId: record.roleId }, { projection: { _id: 0, name: 1 } });
    const target = record.scope?.ref ? await realms().byId(record.scope.ref) : null;
    return {
      assignmentId: record.assignmentId,
      subjectId: record.subjectId,
      roleId: record.roleId,
      ...(role?.name ? { roleName: role.name } : {}),
      ...(record.scope?.ref ? { targetRealmId: record.scope.ref } : {}),
      ...(target?.name ? { targetRealm: target.name } : {}),
      ...(record.grantedBy ? { grantedBy: record.grantedBy } : {}),
      grantedAt: record.grantedAt,
      ...(record.expiresAt ? { expiresAt: record.expiresAt } : {}),
      ...(record.justification ? { justification: record.justification } : {}),
    };
  }

  fastify.get('/realms/:realm/administrable-realms', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listAdministrableRealms',
      tags: ['authorization'],
      summary: 'Which realms the caller may administer',
      description:
        'No applicable standard; this is the multi-realm administration model, where a principal has '
        + 'one home realm and may hold assignments there that name another realm. The home realm is '
        + 'always first in the answer and is always present. A caller with no cross-realm grant gets '
        + 'exactly one entry, which is the ordinary case and the reason a client can render a switcher '
        + 'only when there is something to switch between. The permissions are reported per realm '
        + 'because they differ: a grant over another realm is usually narrower than what its holder '
        + 'has at home.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The realms this principal may administer, home realm first.',
          type: 'object',
          additionalProperties: false,
          required: ['realms'],
          properties: { realms: { type: 'array', items: administrableRealmView } },
          examples: [{
            realms: [{
              realmId: 'd1a2b3c4-0001-0001-0001-000000000001',
              name: 'acme',
              displayName: 'Acme',
              home: true,
              roles: ['manager'],
              permissions: [{ resource: 'identities', action: 'view' }],
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    return reply.send({
      realms: await decisions().administrableRealms(
        caller.homeRealmId, caller.subjectId, AUTHORITY_RESOURCE_SERVER,
      ),
    });
  });

  fastify.get('/realms/:realm/realm-grants', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listRealmGrants',
      tags: ['authorization'],
      summary: 'Assignments in this realm that name another realm',
      description:
        'No applicable standard; multi-realm administration. Every grant that crosses an isolation '
        + 'boundary is listed here in the realm that HOLDS it, because that is the realm whose '
        + 'principals it empowers and the realm whose administrator can take it back. A crossing '
        + 'nobody can enumerate is the one an auditor cannot ask about.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'Every cross-realm grant held in this realm.',
          type: 'object',
          additionalProperties: false,
          required: ['grants'],
          properties: { grants: { type: 'array', items: grantView } },
          examples: [{ grants: [grantView.examples[0]] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits reading assignments.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const decision = await decisions().checkIn(
      caller.homeRealmId, caller.subjectId, AUTHORITY_RESOURCE_SERVER, 'assignments', 'view', caller.realmId,
    );
    if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));

    const held = await assignments()
      .find({ realmId: caller.realmId, 'scope.kind': REALM_SCOPE_KIND }, { projection: { _id: 0 } })
      .toArray();
    return reply.send({ grants: await Promise.all(held.map(describe)) });
  });

  fastify.post('/realms/:realm/realm-grants', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'grantRealmAdministration',
      tags: ['authorization'],
      summary: 'Let a principal of this realm administer another',
      description:
        'No applicable standard; multi-realm administration. The assignment is written in the '
        + 'principal\'s own realm and its scope names the realm it reaches, so the principal gains no '
        + 'second identity, no second set of credentials and no token any other realm would accept. '
        + 'The role is one of THIS realm\'s roles, because a realm does not get to name another '
        + 'realm\'s roles. Granting one is recorded naming both realms.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['subjectId', 'targetRealm', 'roleName', 'justification'],
        additionalProperties: false,
        properties: {
          subjectId: { type: 'string', minLength: 1, description: 'A principal of this realm.' },
          targetRealm: { type: 'string', minLength: 1, description: 'The realm to be administered, by name.' },
          roleName: { type: 'string', minLength: 1, description: 'A role of THIS realm, whose permissions the grant carries.' },
          justification: { type: 'string', minLength: 1, description: 'Why the boundary is being crossed. Required, because a crossing with no stated reason cannot be reviewed.' },
          expiresAt: { type: 'string', description: 'When the grant lapses. Absent means it stands until revoked.' },
        },
      },
      response: {
        201: { ...grantView, description: 'The grant, in force.' },
        400: { $ref: 'Problem#', description: 'The target realm is this realm, or the request is incomplete.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits managing assignments.' },
        404: { $ref: 'Problem#', description: 'No such realm, principal or role.' },
        409: { $ref: 'Problem#', description: 'That principal already administers that realm through that role.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const body = request.body as {
      subjectId: string; targetRealm: string; roleName: string; justification: string; expiresAt?: string;
    };

    const decision = await decisions().checkIn(
      caller.homeRealmId, caller.subjectId, AUTHORITY_RESOURCE_SERVER, 'assignments', 'manage', caller.realmId,
    );
    if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));

    const holder = await realms().byId(caller.realmId);
    if (!holder) return reply.status(404).send(problem(404, 'Unknown realm'));

    const target = await realms().byName(body.targetRealm);
    if (!target) return reply.status(404).send(problem(404, 'Unknown realm', 'No realm answers to that name.'));
    // A grant pointing at its own realm would say nothing an unscoped assignment does not, and would
    // then be a second way to express one fact.
    if (target.realmId === holder.realmId) {
      return reply.status(400).send(problem(400, 'That is this realm', 'A principal already administers their own realm through an ordinary assignment.'));
    }

    const subject = await fastify.db.collection<{ subjectId: string; realmId: string }>(PRINCIPAL_COLLECTION)
      .findOne({ realmId: holder.realmId, subjectId: body.subjectId }, { projection: { _id: 0, subjectId: 1 } });
    if (!subject) return reply.status(404).send(problem(404, 'Unknown principal', 'No principal of this realm has that subject.'));

    const role = await fastify.db.collection<RoleRecord>(ROLE_COLLECTION)
      .findOne({ realmId: holder.realmId, name: body.roleName }, { projection: { _id: 0, roleId: 1, name: 1 } });
    if (!role) return reply.status(404).send(problem(404, 'Unknown role', 'This realm defines no role by that name.'));

    const existing = await assignments().findOne({
      realmId: holder.realmId,
      subjectId: body.subjectId,
      roleId: role.roleId,
      'scope.kind': REALM_SCOPE_KIND,
      'scope.ref': target.realmId,
    });
    if (existing) return reply.status(409).send(problem(409, 'Already granted'));

    const record: RoleAssignmentRecord = {
      realmId: holder.realmId,
      tenantId: holder.tenantId,
      assignmentId: `rgrant-${randomUUID()}`,
      subjectId: body.subjectId,
      roleId: role.roleId,
      scope: { kind: REALM_SCOPE_KIND, ref: target.realmId },
      grantedBy: caller.subjectId,
      grantedAt: new Date().toISOString(),
      ...(body.expiresAt ? { expiresAt: body.expiresAt } : {}),
      justification: body.justification.trim(),
      meta: newMeta('RoleAssignment'),
    };
    await assignments().insertOne(record);

    // Recorded in BOTH realms. The realm that holds the grant needs it because its principal gained
    // authority; the realm that is now administrable needs it because somebody outside it did.
    for (const realm of [holder, target]) {
      void events().record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authorization',
        action: 'authorization.cross_realm_granted',
        outcome: 'success',
        subjectId: body.subjectId,
        principalSubjectId: caller.subjectId,
        // The principal who gained authority over another realm. The event is about them and they
        // did not perform it, so without this it would reach the granter and nobody else.
        stakeholderSubjectIds: [body.subjectId, caller.subjectId],
        detail: {
          homeRealm: holder.name,
          homeRealmId: holder.realmId,
          targetRealm: target.name,
          targetRealmId: target.realmId,
          roleName: role.name,
          justification: record.justification,
        },
        target: { type: 'realm', ref: target.realmId },
      });
    }

    return reply.status(201).send(await describe(record));
  });

  fastify.delete('/realms/:realm/realm-grants/:assignmentId', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'revokeRealmGrant',
      tags: ['authorization'],
      summary: 'Take back administration of another realm',
      description:
        'No applicable standard; multi-realm administration. The grant is deleted rather than left to '
        + 'expire, and takes effect at once: permissions are resolved from the stored assignment on '
        + 'every request, so nothing survives in a token that was already issued beyond its own short '
        + 'life. Recorded naming both realms, like the grant was.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'assignmentId'],
        properties: { realm: { type: 'string' }, assignmentId: { type: 'string' } },
      },
      response: {
        200: {
          description: 'Revoked.',
          type: 'object',
          additionalProperties: false,
          required: ['revoked', 'assignmentId'],
          properties: { revoked: { type: 'boolean' }, assignmentId: { type: 'string' } },
          examples: [{ revoked: true, assignmentId: 'rgrant-9f21' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits managing assignments.' },
        404: { $ref: 'Problem#', description: 'No such cross-realm grant in this realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { assignmentId } = request.params as { assignmentId: string };

    const decision = await decisions().checkIn(
      caller.homeRealmId, caller.subjectId, AUTHORITY_RESOURCE_SERVER, 'assignments', 'manage', caller.realmId,
    );
    if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));

    const held = await assignments().findOne(
      { realmId: caller.realmId, assignmentId, 'scope.kind': REALM_SCOPE_KIND },
      { projection: { _id: 0 } },
    );
    if (!held) return reply.status(404).send(problem(404, 'No such grant'));

    await assignments().deleteOne({ realmId: caller.realmId, assignmentId });

    const holder = await realms().byId(caller.realmId);
    const target = held.scope?.ref ? await realms().byId(held.scope.ref) : null;
    for (const realm of [holder, target]) {
      if (!realm) continue;
      void events().record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authorization',
        action: 'authorization.cross_realm_revoked',
        outcome: 'success',
        subjectId: held.subjectId,
        principalSubjectId: caller.subjectId,
        // The principal whose authority was taken back, and the caller who took it.
        stakeholderSubjectIds: [held.subjectId, caller.subjectId],
        detail: {
          homeRealm: holder?.name,
          homeRealmId: caller.realmId,
          targetRealm: target?.name,
          targetRealmId: held.scope?.ref,
        },
        target: { type: 'realm', ref: held.scope?.ref ?? caller.realmId },
      });
    }

    return reply.send({ revoked: true, assignmentId });
  });
}
