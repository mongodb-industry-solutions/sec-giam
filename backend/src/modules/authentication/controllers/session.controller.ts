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
import { listOAuthClients } from '../../oauth/services/clientAuth.service';
import { SessionRecord, isLive } from '../models/session.model';
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
      /**
       * The same applications by the name they are registered under.
       *
       * Alongside `clientIds` rather than instead of them: the id is what a filter and a support
       * question are phrased in, the name is what a person recognises. An unregistered id appears
       * as itself rather than being dropped, because a token held by something no longer registered
       * is exactly what a reviewer needs to see.
       */
      applications: {
        type: 'array',
        items: { type: 'string' },
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
      applications: ['Identity Console'],
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

  function view(
    session: SessionRecord,
    currentSessionId?: string,
    names?: ReadonlyMap<string, string>,
    clientNames?: ReadonlyMap<string, string>,
  ) {
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
      applications: (session.clientIds ?? []).map((clientId) => clientNames?.get(clientId) ?? clientId),
      current: session.sessionId === currentSessionId,
      ...(Object.keys(origin).length > 0 ? { origin } : {}),
    };
  }

  /**
   * Ending ONE session, all of it, once.
   *
   * The whole act lives here because ending one and ending a selection must be the same thing: the
   * record terminated, the tokens revoked, the epoch raised, the applications told and the trail
   * written. A bulk route with its own copy of this would be the place one of those five silently
   * goes missing.
   *
   * Null means "not reachable by this caller, or not there" and the two are deliberately one
   * answer: distinguishing them would let anybody learn which session identifiers are real.
   */
  async function endOne(
    realm: { realmId: string; tenantId: string; issuer: string },
    caller: { subjectId: string; sessionId?: string },
    sessionId: string,
  ) {
    const sessions = new SessionService(fastify.db);
    const session = await sessions.find(realm.realmId, sessionId);
    // Absence IS the answer now: a terminated session is a deleted one.
    if (!session) return null;

    if (session.subjectId !== caller.subjectId) {
      const access = await authorityAccess(fastify.db, realm.realmId, caller.subjectId);
      if (!access.can('sessions', 'manage') || !access.realmWide) return null;
    }

    const issuer = new TokenIssuer(fastify.db, new KeyRing(new MongoSigningKeyStore(fastify.db)));
    const outcome = await sessions.terminate(realm.realmId, sessionId, 'revoked', issuer);
    if (!outcome.terminated) return null;

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

    return {
      terminated: true,
      sessionId,
      revokedTokens: outcome.revokedTokens,
      // The console reads this and signs itself out rather than sitting on a token that is now dead.
      wasCurrentSession: caller.sessionId === sessionId,
      notified: notified.delivered,
      notificationFailures: notified.failed,
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
          q: {
            type: 'string',
            description:
              'Matches the user name, the formatted name or the subject id of the person signed in. '
              + 'Requires a realm-wide role, because it is a question about other people.',
          },
          clientId: {
            type: 'string',
            description:
              'Only sessions holding a token for this application. Needs no realm-wide role: '
              + 'narrowing your OWN sessions to one application is still a question about yourself.',
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
          required: ['sessions', 'total', 'scope', 'applications'],
          properties: {
            sessions: { type: 'array', items: sessionView },
            total: { type: 'integer' },
            scope: { type: 'string', enum: ['mine', 'realm'], description: 'What was actually answered, which may be narrower than what was asked.' },
            applications: {
              type: 'array',
              description:
                'Every application registered in this realm, so a filter can offer them by name. '
                + 'From the registry rather than from the page: derived from the page it would '
                + 'shrink as soon as one was chosen and the filter could not be undone.',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['clientId', 'clientName'],
                properties: {
                  clientId: { type: 'string' },
                  clientName: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            sessions: [sessionView.examples[0]],
            total: 1,
            scope: 'mine',
            applications: [{ clientId: 'giam-console', clientName: 'Identity Console' }],
          }],
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

    const query = request.query as {
      subjectId?: string; scope?: 'mine' | 'realm'; q?: string; clientId?: string; skip?: number; limit?: number;
    };
    const sessions = new SessionService(fastify.db);
    const narrowing = Boolean(query.subjectId && query.subjectId !== caller.subjectId) || Boolean(query.q);
    const wantsOthers = query.scope === 'realm' || narrowing;

    if (wantsOthers) {
      const access = await authorityAccess(fastify.db, realm.realmId, caller.subjectId);
      if (!access.can('sessions', 'view') || !access.realmWide) {
        return reply.status(403).send(problem(
          403,
          'Not permitted',
          'No role held by this principal reaches the sessions of another principal.',
        ));
      }
    }

    /**
     * The entitlement and the filters resolve into ONE narrowing, and then there is one read.
     *
     * A self-scoped caller arrives with their own id already in `subjectIds`, so the boundary is not
     * a separate branch that could be forgotten. Undefined means "every subject", which only a
     * realm-wide caller ever reaches.
     */
    let subjectIds: string[] | undefined = wantsOthers ? undefined : [caller.subjectId];
    if (wantsOthers && query.subjectId) subjectIds = [query.subjectId];
    if (wantsOthers && query.q) {
      const matched = await directory.subjectIdsMatching(realm.realmId, query.q);
      // Intersected rather than replaced, so a search inside an already named subject cannot widen
      // the answer back out. No match is an empty answer, never an unfiltered one.
      subjectIds = subjectIds ? subjectIds.filter((id) => matched.includes(id)) : matched;
      if (subjectIds.length === 0) {
        return reply.send({ sessions: [], total: 0, scope: 'realm', applications: [] });
      }
    }

    const page = await sessions.list(realm.realmId, {
      ...(subjectIds ? { subjectIds } : {}),
      ...(query.clientId ? { clientId: query.clientId } : {}),
      skip: query.skip,
      limit: query.limit,
    });

    // One read each for the names on the page and for the applications in the realm, never one per
    // row: a page of twenty rows used to be twenty client lookups waiting to be written.
    const [names, registered] = await Promise.all([
      directory.namesFor(realm.realmId, page.sessions.map((session) => session.subjectId)),
      listOAuthClients(fastify.db, realm.realmId),
    ]);
    const clientNames = new Map(registered.map((client) => [client.clientId, client.clientName ?? client.clientId]));

    return reply.send({
      sessions: page.sessions.map((session) => view(session, caller.sessionId, names, clientNames)),
      total: page.total,
      scope: wantsOthers ? 'realm' : 'mine',
      /**
       * The applications a filter can offer, from the registry rather than from the page.
       *
       * Derived from the page it would shrink as soon as one was chosen, which makes the control
       * unable to undo itself. Sent with the list because the caller needs no `clients:view` to read
       * their own sessions, and a second gated endpoint would refuse exactly the people this screen
       * serves.
       */
      applications: registered
        .map((client) => ({ clientId: client.clientId, clientName: client.clientName ?? client.clientId }))
        .sort((a, b) => a.clientName.localeCompare(b.clientName)),
    });
  });

  /**
   * One session in full, for the question a list cannot answer.
   *
   * Same reachability rule as ending one, and the same 404: a session belonging to somebody else is
   * NOT FOUND to a self-scoped caller rather than refused, because 403 and 404 together let anyone
   * enumerate which session identifiers are real.
   *
   * NO TOKEN IS RETURNED, and none could be. This authority stores no token (see `session.model.ts`):
   * an access token and a refresh token are both JWTs, verified without a database read, and
   * revocation works by the ABSENCE of this document plus the epoch. So there is no token registry
   * to publish. Nor would it be published if there were: handing a bearer token to whoever holds
   * `sessions:view` turns a read permission into impersonation.
   *
   * What replaces it is the two levers that actually govern the tokens of this session, `epoch` and
   * `refreshGeneration`, plus the authentication context they were issued under. That is what a
   * reviewer needs in order to reason about what is still valid.
   */
  fastify.get(`${base}/:sessionId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getSession',
      tags: ['sessions'],
      summary: 'One session in full',
      description:
        'No applicable standard. The session, who it belongs to, and the authentication context it '
        + 'was established under. Reachable for your own always, and for somebody else with a '
        + 'realm-wide role; an unreachable one answers 404 rather than 403 so session identifiers '
        + 'cannot be enumerated. No token is returned: none is stored, and a bearer token on a read '
        + 'surface would make viewing a session equivalent to using it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'sessionId'],
        properties: { realm: { type: 'string' }, sessionId: { type: 'string' } },
      },
      response: {
        200: {
          description: 'The session, its owner, and how it was authenticated.',
          type: 'object',
          additionalProperties: false,
          required: ['session', 'owner', 'authentication'],
          properties: {
            session: sessionView,
            owner: {
              type: 'object',
              additionalProperties: false,
              description:
                'Who the session belongs to. Deliberately no email or phone: both are encrypted '
                + 'personal data, and a session page is not a reason to decrypt them. The identity '
                + 'page is where a principal is read, and a caller links to it rather than '
                + 'restating it here.',
              required: ['subjectId'],
              properties: {
                subjectId: { type: 'string' },
                userName: { type: 'string' },
                kind: { type: 'string', description: 'A person or a workload.' },
                active: { type: 'boolean' },
                lifecycleState: { type: 'string' },
              },
            },
            authentication: {
              type: 'object',
              additionalProperties: false,
              description: 'How this session was established, and what governs the tokens issued under it.',
              required: ['epoch', 'refreshGeneration', 'tokensStored'],
              properties: {
                domainId: { type: 'string', description: 'The authentication path used.' },
                domainName: { type: 'string' },
                establishedForClientId: { type: 'string', description: 'The application the session was opened for.' },
                establishedForClientName: { type: 'string' },
                acr: { type: 'string', description: 'NIST SP 800-63 assurance level reached.' },
                amr: { type: 'array', items: { type: 'string' }, description: 'RFC 8176 methods used.' },
                credentialId: { type: 'string', description: 'The factor that authenticated.' },
                ticketId: { type: 'string', description: 'The authorization request this session came from.' },
                epoch: {
                  type: 'integer',
                  description:
                    'Tokens issued below this are retired. Raising it revokes every outstanding '
                    + 'token of this principal without listing any of them.',
                },
                refreshGeneration: {
                  type: 'integer',
                  description:
                    'RFC 9700 rotation with reuse detection. A refresh token presenting a lower '
                    + 'generation is treated as theft and ends the session.',
                },
                tokensStored: {
                  type: 'boolean',
                  description:
                    'Always false, and stated rather than omitted: this authority records no token, '
                    + 'so there is no per-token history here and none is being withheld.',
                },
              },
            },
          },
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No live session this caller can reach.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, sessionId } = request.params as { realm: string; sessionId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const session = await new SessionService(fastify.db).find(realm.realmId, sessionId);
    // A lapsed session is not found either: the list shows only live ones, and a detail page that
    // answered for a dead one would offer an End control over something already gone.
    if (!session || !isLive(session)) return reply.status(404).send(problem(404, 'No such session'));

    if (session.subjectId !== caller.subjectId) {
      const access = await authorityAccess(fastify.db, realm.realmId, caller.subjectId);
      if (!access.can('sessions', 'view') || !access.realmWide) {
        return reply.status(404).send(problem(404, 'No such session'));
      }
    }

    const realms = new RealmService(fastify.db);
    const [owner, names, registered, domains] = await Promise.all([
      directory.findBySubjectId(session.subjectId),
      directory.namesFor(realm.realmId, [session.subjectId]),
      listOAuthClients(fastify.db, realm.realmId),
      session.domainId ? realms.providersFor(realm.realmId) : Promise.resolve([]),
    ]);
    const clientNames = new Map(registered.map((client) => [client.clientId, client.clientName ?? client.clientId]));
    const domain = domains.find((candidate) => candidate.domainId === session.domainId);

    return reply.send({
      session: view(session, caller.sessionId, names, clientNames),
      owner: {
        subjectId: session.subjectId,
        ...(owner?.userName ? { userName: owner.userName } : {}),
        ...(owner?.kind ? { kind: owner.kind } : {}),
        ...(typeof owner?.active === 'boolean' ? { active: owner.active } : {}),
        ...(owner?.lifecycleState ? { lifecycleState: owner.lifecycleState } : {}),
      },
      authentication: {
        ...(session.domainId ? { domainId: session.domainId } : {}),
        ...(domain?.displayName || domain?.name
          ? { domainName: (domain.displayName ?? domain.name) as string }
          : {}),
        ...(session.clientId
          ? {
            establishedForClientId: session.clientId,
            establishedForClientName: clientNames.get(session.clientId) ?? session.clientId,
          }
          : {}),
        ...(session.acr ? { acr: session.acr } : {}),
        ...(session.amr?.length ? { amr: session.amr } : {}),
        ...(session.credentialId ? { credentialId: session.credentialId } : {}),
        ...(session.ticketId ? { ticketId: session.ticketId } : {}),
        epoch: session.epoch,
        refreshGeneration: session.refreshGen,
        tokensStored: false,
      },
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

    const ended = await endOne(realm, caller, sessionId);
    if (!ended) return reply.status(404).send(problem(404, 'No such session'));
    return reply.send(ended);
  });

  /**
   * Ending SEVERAL, because ending them one at a time is the same act repeated.
   *
   * A POST rather than a DELETE with a body: a body on DELETE is permitted by RFC 9110 but its
   * semantics are undefined, so caches and proxies are free to drop it. This names the act instead.
   *
   * Per-session outcomes rather than one verdict. A selection where one row had already lapsed is
   * the normal case, not a failure, and a single status code could only either fail the whole batch
   * for it or hide it. Unreachable and already gone are reported as the SAME outcome, so this cannot
   * be used to enumerate identifiers any more than ending one at a time can.
   *
   * Not transactional, and deliberately so: each termination revokes tokens and notifies
   * applications, and those are not undoable. Rolling back the record after telling the world a
   * session ended would leave the world right and the authority wrong.
   */
  fastify.post(`${base}/terminate`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'terminateSessions',
      tags: ['sessions'],
      summary: 'End several sessions at once',
      description:
        'Standard-adjacent: each termination is delivered as an OpenID Connect Back-Channel Logout '
        + '1.0 notification, exactly as ending one is. Reports an outcome per session; a session '
        + 'this caller cannot reach and one that has already gone are both reported as `notFound`, '
        + 'so a batch cannot be used to discover which identifiers are real.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['sessionIds'],
        additionalProperties: false,
        properties: {
          sessionIds: {
            type: 'array',
            items: { type: 'string' },
            minItems: 1,
            maxItems: 200,
            description: 'Capped at the page size a caller can select, so this cannot become a way to sweep a realm in one call.',
          },
        },
      },
      response: {
        200: {
          description: 'What happened to each session named.',
          type: 'object',
          additionalProperties: false,
          required: ['results', 'terminated', 'wasCurrentSession'],
          properties: {
            terminated: { type: 'integer', description: 'How many actually ended.' },
            wasCurrentSession: {
              type: 'boolean',
              description: 'True when the caller ended their own session among them, so the caller is now signed out.',
            },
            results: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['sessionId', 'outcome'],
                properties: {
                  sessionId: { type: 'string' },
                  outcome: { type: 'string', enum: ['terminated', 'notFound'] },
                  revokedTokens: { type: 'integer' },
                  notified: { type: 'array', items: { type: 'string' } },
                  notificationFailures: { type: 'array', items: { type: 'string' } },
                },
              },
            },
          },
          examples: [{
            terminated: 2,
            wasCurrentSession: false,
            results: [
              { sessionId: 'c41a7de0-90b1-4c1e-9f2a-8d5b3e7c0a12', outcome: 'terminated', revokedTokens: 0, notified: ['giam-console'], notificationFailures: [] },
              { sessionId: '0d9b1f44-2a77-4e2a-9d31-6b0c5a9f7e11', outcome: 'notFound' },
            ],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const { sessionIds } = request.body as { sessionIds: string[] };
    // Deduplicated: the same id twice would otherwise be reported as one termination and one
    // `notFound`, which reads as a partial failure of something that fully succeeded.
    const wanted = [...new Set(sessionIds)];

    const results = [];
    let terminated = 0;
    let wasCurrentSession = false;
    /**
     * Sequential, not `Promise.all`.
     *
     * Each termination raises the epoch of its subject and notifies applications over the network.
     * Two hundred of those at once is a burst aimed at every relying party at the same moment, and
     * the epoch write is per subject, so concurrent ones for one person would contend for the same
     * document to reach the same final value.
     *
     * The caller's OWN session is left for last, so ending a selection that includes it does not
     * revoke the token being used to end the rest.
     */
    const ordered = [
      ...wanted.filter((id) => id !== caller.sessionId),
      ...wanted.filter((id) => id === caller.sessionId),
    ];
    for (const id of ordered) {
      const ended = await endOne(realm, caller, id);
      if (!ended) {
        results.push({ sessionId: id, outcome: 'notFound' as const });
        continue;
      }
      terminated += 1;
      if (ended.wasCurrentSession) wasCurrentSession = true;
      results.push({
        sessionId: id,
        outcome: 'terminated' as const,
        revokedTokens: ended.revokedTokens,
        notified: ended.notified,
        notificationFailures: ended.notificationFailures,
      });
    }

    return reply.send({ terminated, wasCurrentSession, results });
  });
}
