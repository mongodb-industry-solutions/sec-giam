import { FastifyInstance } from 'fastify';
import { DirectoryService } from '../../directory/services/directory.service';
import { RealmService } from '../../realm/services/realm.service';
import { SessionService } from '../services/session.service';
import { LogoutNotifier } from '../services/logoutNotifier.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { authorityAccess } from '../../authorization/services/authorityAccess';
import { SessionRecord } from '../models/session.model';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

/**
 * Where an account is signed in, and ending it.
 *
 * The one surface here that serves both tiers. Seeing where your own account is signed in and being
 * able to end it is basic account security, not an administrative privilege, so an ordinary
 * registered user reaches their own sessions without holding anything. An administrator of the realm
 * additionally reaches everybody's, and that is decided by the scope of the role they hold.
 *
 * The narrowing happens HERE and never in the console. A session belonging to somebody else answers
 * 404 to a self-scoped caller rather than 403, because the two answers together would let anyone
 * enumerate which session identifiers are real.
 *
 * Ending a session is three things and needs all three: the record is terminated, the tokens issued
 * under it are revoked, and the principal's epoch is raised so anything issued under it that was
 * never recorded is retired too. Then the applications holding a token are told, because a logout
 * nobody hears about leaves every one of them still serving.
 */
export async function sessionController(fastify: FastifyInstance) {
  const base = '/realms/:realm/sessions';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const sessionView = {
    type: 'object',
    additionalProperties: false,
    required: ['sessionId', 'subjectId', 'createdAt', 'lastSeenAt', 'expiresAt', 'idleExpiresAt', 'clientIds', 'current'],
    properties: {
      sessionId: { type: 'string' },
      subjectId: { type: 'string' },
      /**
       * The name behind the subject, so a list of sessions reads as people.
       *
       * Absent when the principal is gone, and a caller then shows the id. A session outliving its
       * principal is a real state and inventing a name for it would hide it.
       */
      userName: { type: 'string' },
      createdAt: { type: 'string' },
      lastSeenAt: { type: 'string' },
      expiresAt: { type: 'string', description: 'Absolute end, regardless of activity.' },
      idleExpiresAt: { type: 'string', description: 'Rolling end, moved forward on use.' },
      clientIds: {
        type: 'array',
        items: { type: 'string' },
        description: 'Every application holding a token from this session, and therefore told when it ends.',
      },
      current: { type: 'boolean', description: 'True for the session the calling token was issued under.' },
      origin: {
        type: 'object',
        additionalProperties: false,
        description: 'Coarse only. The address and the user agent are stored hashed, never raw, so a session record is not a place personal data accumulates.',
        properties: {
          addressFingerprint: { type: 'string' },
          deviceFingerprint: { type: 'string' },
        },
      },
    },
    examples: [{
      sessionId: 'c41a7de0-90b1-4c1e-9f2a-8d5b3e7c0a12',
      subjectId: 'a1000070-0000-4000-8000-000000000070',
      createdAt: '2026-08-31T08:41:00.000Z',
      lastSeenAt: '2026-08-31T09:58:00.000Z',
      expiresAt: '2026-08-31T20:41:00.000Z',
      idleExpiresAt: '2026-08-31T10:28:00.000Z',
      clientIds: ['giam-console'],
      current: true,
      origin: { addressFingerprint: '3f9c1a7e', deviceFingerprint: 'b21d80f4' },
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  // Short and one way. Enough to tell two origins apart in a list, never enough to recover either.
  const fingerprint = (hash?: string) => (hash ? hash.slice(0, 8) : undefined);

  const directory = new DirectoryService(fastify.db);

  function view(session: SessionRecord, currentSessionId?: string, names?: ReadonlyMap<string, string>) {
    const origin = {
      ...(session.ipHash ? { addressFingerprint: fingerprint(session.ipHash) } : {}),
      ...(session.userAgentHash ? { deviceFingerprint: fingerprint(session.userAgentHash) } : {}),
    };
    return {
      sessionId: session.sessionId,
      subjectId: session.subjectId,
      ...(names?.get(session.subjectId) ? { userName: names.get(session.subjectId) as string } : {}),
      createdAt: session.createdAt,
      lastSeenAt: session.lastSeenAt,
      expiresAt: session.expiresAt,
      idleExpiresAt: session.idleExpiresAt,
      clientIds: session.clientIds ?? [],
      current: session.sessionId === currentSessionId,
      ...(Object.keys(origin).length > 0 ? { origin } : {}),
    };
  }

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listSessions',
      tags: ['sessions'],
      summary: 'Where an account is signed in',
      description:
        'No applicable standard. A caller always sees their own sessions; seeing another principal\'s '
        + 'requires a role whose scope reaches beyond the holder, and asking without one narrows the '
        + 'answer to the caller rather than refusing it, because a person is always entitled to '
        + 'their own. The origin is a short fingerprint of values stored hashed, never the address '
        + 'or the user agent themselves.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          subjectId: { type: 'string', description: 'Another principal. Requires a realm-wide role.' },
          scope: {
            type: 'string',
            enum: ['mine', 'realm'],
            default: 'mine',
            description: '`realm` lists every live session in the realm. Requires a realm-wide role.',
          },
          skip: { type: 'integer', default: 0 },
          limit: { type: 'integer', default: 20, maximum: 200 },
        },
      },
      response: {
        200: {
          description: 'The live sessions in view, and how many there are.',
          type: 'object',
          additionalProperties: false,
          required: ['sessions', 'total', 'scope'],
          properties: {
            sessions: { type: 'array', items: sessionView },
            total: { type: 'integer' },
            scope: { type: 'string', enum: ['mine', 'realm'], description: 'What was actually answered, which may be narrower than what was asked.' },
          },
          examples: [{ sessions: [sessionView.examples[0]], total: 1, scope: 'mine' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'Another principal was named and no role held reaches them.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const query = request.query as { subjectId?: string; scope?: 'mine' | 'realm'; skip?: number; limit?: number };
    const sessions = new SessionService(fastify.db);
    const wantsOthers = query.scope === 'realm' || (Boolean(query.subjectId) && query.subjectId !== caller.subjectId);

    if (wantsOthers) {
      const access = await authorityAccess(fastify.db, realm.realmId, caller.subjectId);
      if (!access.can('sessions', 'view') || !access.realmWide) {
        return reply.status(403).send(problem(
          403,
          'Not permitted',
          'No role held by this principal reaches another principal\'s sessions.',
        ));
      }
      if (query.subjectId) {
        const held = await sessions.listFor(realm.realmId, query.subjectId);
        const names = await directory.namesFor(realm.realmId, held.map((session) => session.subjectId));
        return reply.send({
          sessions: held.map((session) => view(session, caller.sessionId, names)),
          total: held.length,
          scope: 'realm',
        });
      }
      const page = await sessions.listForRealm(realm.realmId, { skip: query.skip, limit: query.limit });
      // One query for the whole page, not one per row.
      const names = await directory.namesFor(realm.realmId, page.sessions.map((session) => session.subjectId));
      return reply.send({
        sessions: page.sessions.map((session) => view(session, caller.sessionId, names)),
        total: page.total,
        scope: 'realm',
      });
    }

    const own = await sessions.listFor(realm.realmId, caller.subjectId);
    const names = await directory.namesFor(realm.realmId, own.map((session) => session.subjectId));
    return reply.send({
      sessions: own.map((session) => view(session, caller.sessionId, names)),
      total: own.length,
      scope: 'mine',
    });
  });

  fastify.delete(`${base}/:sessionId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'terminateSession',
      tags: ['sessions'],
      summary: 'End a session everywhere',
      description:
        'Standard-adjacent: the termination is delivered as an OpenID Connect Back-Channel Logout 1.0 '
        + 'notification to every application holding a token from it. The record is terminated, the '
        + 'tokens issued under it are revoked, and the principal\'s epoch is raised so anything the '
        + 'authority never recorded is retired with it. A session belonging to somebody else is not '
        + 'found rather than refused, so this cannot be used to learn which identifiers are real.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'sessionId'],
        properties: { realm: { type: 'string' }, sessionId: { type: 'string' } },
      },
      response: {
        200: {
          description: 'Ended, and who was told.',
          type: 'object',
          additionalProperties: false,
          required: ['terminated', 'sessionId', 'revokedTokens', 'wasCurrentSession'],
          properties: {
            terminated: { type: 'boolean' },
            sessionId: { type: 'string' },
            revokedTokens: { type: 'integer' },
            wasCurrentSession: {
              type: 'boolean',
              description: 'True when the caller ended the session their own token came from, so the caller is now signed out.',
            },
            notified: { type: 'array', items: { type: 'string' } },
            notificationFailures: { type: 'array', items: { type: 'string' } },
          },
          examples: [{
            terminated: true,
            sessionId: 'c41a7de0-90b1-4c1e-9f2a-8d5b3e7c0a12',
            revokedTokens: 3,
            wasCurrentSession: false,
            notified: ['giam-console'],
            notificationFailures: [],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such live session this caller can reach.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, sessionId } = request.params as { realm: string; sessionId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const sessions = new SessionService(fastify.db);
    const session = await sessions.find(realm.realmId, sessionId);
    // Absence IS the answer now: a terminated session is a deleted one.
    if (!session) return reply.status(404).send(problem(404, 'No such session'));

    if (session.subjectId !== caller.subjectId) {
      const access = await authorityAccess(fastify.db, realm.realmId, caller.subjectId);
      // 404 rather than 403: a caller who may not reach it must not learn that it exists.
      if (!access.can('sessions', 'manage') || !access.realmWide) {
        return reply.status(404).send(problem(404, 'No such session'));
      }
    }

    const issuer = new TokenIssuer(fastify.db, new KeyRing(new MongoSigningKeyStore(fastify.db)));
    const outcome = await sessions.terminate(realm.realmId, sessionId, 'revoked', issuer);
    if (!outcome.terminated) return reply.status(404).send(problem(404, 'No such session'));

    const notified = await new LogoutNotifier(fastify.db)
      .notify(outcome.notify, realm, session.subjectId, sessionId);

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'session',
      action: 'authentication.session.terminated',
      outcome: 'success',
      subjectId: session.subjectId,
      detail: { endedBy: caller.subjectId, revokedTokens: outcome.revokedTokens },
    });

    return reply.send({
      terminated: true,
      sessionId,
      revokedTokens: outcome.revokedTokens,
      // The console reads this and signs itself out rather than sitting on a token that is now dead.
      wasCurrentSession: caller.sessionId === sessionId,
      notified: notified.delivered,
      notificationFailures: notified.failed,
    });
  });
}
