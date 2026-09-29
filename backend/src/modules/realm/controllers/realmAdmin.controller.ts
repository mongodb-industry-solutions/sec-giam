import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { RealmService, isRealmRefusal } from '../services/realm.service';
import { RealmRecord } from '../models/realm.model';
import { authorityAccess, refusal } from '../../authorization/services/authorityAccess';
import { recordConfigurationChange } from '../../audit/services/configurationChange';
import { resolvePrincipal, type CallingPrincipal } from '../../../vendors/middleware/principalAuth';
import { JwtTokenFormat } from '../../oauth/services/jwtTokenFormat';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { problem } from '../../../shared/models/problem';

/**
 * Creating and reconfiguring a realm itself, not what lives inside one.
 *
 * **No applicable standard.** Every other administrative surface in this authority is reached
 * through `/realms/:realm/...` because it acts INSIDE a realm; this acts ON one, so it has no realm
 * to nest under and lives at `/api/v1/realms` directly.
 *
 * Gated on the CALLER'S OWN (home) realm, because that is the only realm a brand-new realm could
 * possibly be judged against: there is nothing else to check a not-yet-created realm's permissions
 * in. `realms:manage` is already a grantable permission on `manager` (`roles.json`); this is the
 * first route that actually checks it.
 *
 * Deliberately no DELETE. Withdrawing a client or retiring a policy has a defined, reversible
 * meaning; deleting a realm does not; every session, principal, client and credential scoped to it
 * would need a decision this authority has not made. `enabled: false` is the reversible way to stop
 * one, exactly as a domain already offers for one authentication path.
 */
export async function realmAdminController(fastify: FastifyInstance) {
  /**
   * `requirePrincipal` resolves against the realm NAMED IN THE PATH, which these routes have none
   * of: they act on realms themselves, not inside one. The token still names its own issuer, so the
   * caller's identity is resolved from that instead. There is never a "target" distinct from
   * "home" here, because there is nothing else in the path to act on; `resolvePrincipal` is called
   * with the token's own realm both times, which is what keeps its cross-realm-grant branch from
   * ever triggering for what is, structurally, always a same-realm request.
   */
  async function requireHomePrincipal(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    request.bearerProtected = true;
    const authorization = request.headers.authorization;
    const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
    const unverified = token ? await new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(fastify.db)), '').inspect(token) : null;
    const issuer = typeof unverified?.iss === 'string' ? unverified.iss : '';
    const home = issuer ? await new RealmService(fastify.db).byIssuer(issuer) : null;
    const principal: CallingPrincipal | null = home
      ? await resolvePrincipal(fastify.db, home.name, authorization)
      : null;
    if (!principal) {
      reply.status(401).send(problem(401, 'Unauthorized', 'A valid access token is required.'));
      return;
    }
    request.principal = principal;
  }

  const realmView = {
    type: 'object',
    additionalProperties: true,
    example: {
      realmId: 'd1a2b3c4-0001-0001-0001-000000000001',
      name: 'acme',
      displayName: 'Acme',
      issuer: 'https://issuer.example/api/v1/realms/acme',
      enabled: true,
      aliases: [],
      tokenPolicy: {
        accessTokenTtlSeconds: 300, refreshTokenTtlSeconds: 2_592_000, codeTtlSeconds: 120,
        sessionIdleTtlSeconds: 3_600, sessionMaxTtlSeconds: 43_200,
      },
      branding: { displayName: 'Acme' },
      demoMode: false,
    },
  } as const;

  const writableBody = {
    displayName: { type: 'string', minLength: 1 },
    notice: { type: 'string' },
    enabled: { type: 'boolean' },
    demoMode: { type: 'boolean' },
    clientEnforcement: { type: 'string', enum: ['strict', 'soft'] },
    branding: {
      type: 'object',
      additionalProperties: false,
      properties: {
        displayName: { type: 'string' },
        logoUri: { type: 'string' },
        primaryColor: { type: 'string' },
        backgroundStyle: { type: 'string' },
      },
    },
    tokenPolicy: {
      type: 'object',
      additionalProperties: false,
      properties: {
        accessTokenTtlSeconds: { type: 'integer', minimum: 60 },
        refreshTokenTtlSeconds: { type: 'integer', minimum: 60 },
        codeTtlSeconds: { type: 'integer', minimum: 30 },
        sessionIdleTtlSeconds: { type: 'integer', minimum: 60 },
        sessionMaxTtlSeconds: { type: 'integer', minimum: 60 },
      },
    },
  } as const;

  fastify.get('/realms', {
    preHandler: requireHomePrincipal,
    schema: {
      operationId: 'listRealms',
      tags: ['realms'],
      summary: 'Every realm this deployment hosts',
      description:
        '**No applicable standard.** Realm-wide by nature: a realm is a trust boundary, so listing '
        + 'more than the caller\'s own home realm is always an oversight read, gated the same way '
        + 'reading another principal\'s record anywhere else in this authority is.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          type: 'object', additionalProperties: false, required: ['realms'],
          properties: { realms: { type: 'array', items: realmView } },
          examples: [{ realms: [realmView.example] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants sight of realms beyond the caller\'s own.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const access = await authorityAccess(fastify.db, caller.homeRealmId, caller.subjectId);
    if (!access.can('realms', 'view') || !access.realmWide) {
      // Not refused outright: a principal is always entitled to read their own realm's record, the
      // same fallback `security-events` and other oversight surfaces already use.
      const own = await new RealmService(fastify.db).byId(caller.homeRealmId);
      return reply.send({ realms: own ? [own] : [] });
    }
    return reply.send({ realms: await new RealmService(fastify.db).list() });
  });

  fastify.post('/realms', {
    preHandler: requireHomePrincipal,
    schema: {
      operationId: 'createRealm',
      tags: ['realms'],
      summary: 'Provision a new realm',
      description:
        '**No applicable standard.** Provisions the realm, its own internal directory (so it has '
        + 'somewhere for a principal to belong to) and a published signing key, together: a realm '
        + 'missing any one of the three is not usable, and this is the one call that leaves it ready '
        + 'to sign somebody in immediately.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'displayName'],
        properties: {
          name: { type: 'string', minLength: 1, description: 'Slug. Becomes part of the issuer URL and cannot be changed afterwards.' },
          ...writableBody,
        },
      },
      response: {
        201: { ...realmView, description: 'The realm as created.' },
        400: { $ref: 'Problem#', description: 'Not a valid realm name.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers realms.' },
        409: { $ref: 'Problem#', description: 'That name is already taken.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const access = await authorityAccess(fastify.db, caller.homeRealmId, caller.subjectId);
    if (!access.can('realms', 'manage') || !access.realmWide) {
      return reply.status(403).send(problem(403, 'Not permitted', refusal('realms', 'manage')));
    }

    const body = request.body as Parameters<RealmService['create']>[0];
    const outcome = await new RealmService(fastify.db).create(body);
    if (isRealmRefusal(outcome)) {
      return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));
    }

    // `before: null` names what created means: there was nothing here, and now there is exactly
    // this record, which is what makes standing the realm back up from the trail alone possible.
    await recordConfigurationChange(fastify.db, {
      realmId: outcome.realmId,
      tenantId: outcome.tenantId,
      what: 'realm',
      ref: outcome.realmId,
      operation: 'created',
      actorSubjectId: caller.subjectId,
      before: null,
      after: outcome as unknown as Record<string, unknown>,
    });
    return reply.status(201).send(outcome);
  });

  fastify.get('/realms/:realm', {
    preHandler: requireHomePrincipal,
    schema: {
      operationId: 'getRealm',
      tags: ['realms'],
      summary: 'One realm',
      description:
        '**No applicable standard.** The caller\'s own home realm always resolves; reading another '
        + 'is the same `realms:view` oversight permission `GET /api/v1/realms` already requires.',
      security: [{ bearerAuth: [] }],
      params: { type: 'object', required: ['realm'], properties: { realm: { type: 'string' } } },
      response: {
        200: { ...realmView, description: 'The realm.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants sight of this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName } = request.params as { realm: string };
    const target = await new RealmService(fastify.db).byName(realmName);
    if (!target) return reply.status(404).send(problem(404, 'No such realm'));

    if (target.realmId !== caller.homeRealmId) {
      const access = await authorityAccess(fastify.db, caller.homeRealmId, caller.subjectId);
      if (!access.can('realms', 'view') || !access.realmWide) {
        return reply.status(403).send(problem(403, 'Not permitted', refusal('realms', 'view')));
      }
    }
    return reply.send(target);
  });

  fastify.patch('/realms/:realm', {
    preHandler: requireHomePrincipal,
    schema: {
      operationId: 'updateRealm',
      tags: ['realms'],
      summary: 'Change a realm\'s own configuration',
      description:
        '**No applicable standard.** `name` cannot be changed here: it is embedded in the issuer '
        + 'URL and in every token, alias and lookup that already resolved on it, so changing it would '
        + 'be a new realm wearing an old one\'s identifier rather than an edit.',
      security: [{ bearerAuth: [] }],
      params: { type: 'object', required: ['realm'], properties: { realm: { type: 'string' } } },
      body: { type: 'object', additionalProperties: false, properties: writableBody },
      response: {
        200: { ...realmView, description: 'The realm, as it now stands.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers realms.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName } = request.params as { realm: string };
    const target = await new RealmService(fastify.db).byName(realmName);
    if (!target) return reply.status(404).send(problem(404, 'No such realm'));

    const access = await authorityAccess(fastify.db, caller.homeRealmId, caller.subjectId);
    if (!access.can('realms', 'manage') || !access.realmWide) {
      return reply.status(403).send(problem(403, 'Not permitted', refusal('realms', 'manage')));
    }

    const updated = await new RealmService(fastify.db).update(target.realmId, request.body as object);
    if (!updated) return reply.status(404).send(problem(404, 'No such realm'));

    await recordConfigurationChange(fastify.db, {
      realmId: target.realmId,
      tenantId: target.tenantId,
      what: 'realm',
      ref: target.realmId,
      operation: 'updated',
      actorSubjectId: caller.subjectId,
      before: target as unknown as Record<string, unknown>,
      after: updated as unknown as Record<string, unknown>,
    });
    return reply.send(updated);
  });
}
