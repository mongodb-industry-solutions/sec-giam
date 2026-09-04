import { FastifyInstance } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { SessionService, isSessionLimitRefusal } from '../services/session.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { authenticationMethods } from '../../../shared/ports';
import { bindAuthenticationMethods } from '../services/authenticationMethods';
import { amrFor } from '../models/authenticationContext';
import { bindCredentialStores } from '../../directory/services/credentialStores';
import { SESSION_COLLECTION } from '../../../shared/models/collections';
import { SessionRecord } from '../models/session.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Sign-in at the authority's own page.
 *
 * No applicable standard, and that is worth stating rather than reaching for a grant that looks
 * close. The resource-owner password grant is removed in OAuth 2.1 precisely because an application
 * should never collect a credential on the authority's behalf; here there is no application in the
 * middle, because this IS the authority's page. What it produces is a SESSION, and the standard flows
 * then run on top of it.
 *
 * A failure says only that the attempt failed. Distinguishing an unknown principal from a wrong
 * credential turns the endpoint into an account-enumeration oracle, and the person signing in cannot
 * act on the difference anyway.
 */
export async function loginController(fastify: FastifyInstance) {
  bindCredentialStores(fastify.db);
  bindAuthenticationMethods(fastify.db);

  fastify.post('/realms/:realm/login', {
    schema: {
      operationId: 'signIn',
      tags: ['authentication'],
      summary: 'Sign in and establish a session',
      description:
        'No applicable standard. Credential entry belongs at the authority, so this is its own page '
        + 'posting to its own endpoint rather than a grant an application could use. It establishes a '
        + 'session; the standard flows run on top of it. A failure never distinguishes an unknown '
        + 'principal from a wrong credential.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['login', 'password'],
        additionalProperties: false,
        properties: {
          login: { type: 'string', description: 'User name or email.', examples: ['ada@example.com'] },
          password: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'Authenticated. A session now exists.',
          type: 'object',
          additionalProperties: false,
          required: ['subjectId', 'sessionId', 'assuranceLevel'],
          properties: {
            subjectId: { type: 'string' },
            sessionId: { type: 'string' },
            userName: { type: 'string', description: 'The login identifier, per SCIM.' },
            displayName: { type: 'string', description: 'The name to show. SCIM `name.formatted`.' },
            assuranceLevel: { type: 'string' },
            method: { type: 'string' },
            sessionEpoch: { type: 'integer' },
          },
          examples: [{
            subjectId: 'ec06cbfa-96e2-4867-892b-b74987e78d7a',
            sessionId: 'a3f1…',
            userName: 'ada.lovelace',
            displayName: 'Ada Lovelace',
            assuranceLevel: 'aal1',
            method: 'password',
            sessionEpoch: 0,
          }],
        },
        401: { $ref: 'Problem#', description: 'The attempt failed. Deliberately no further detail.' },
        429: { $ref: 'Problem#', description: 'The concurrent-session limit on this path refuses a further session.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const { login, password } = request.body as { login: string; password: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm || !realm.enabled) {
      return reply.status(404).send(problem(404, 'Unknown realm'));
    }

    const method = authenticationMethods.resolve('password');
    const resolution = await method.authenticate({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      presented: { login, password },
      ipHash: hashIp(request.ip),
    });

    const audit = new SecurityEventService(fastify.db);
    const directory = new DirectoryService(fastify.db);

    if (!resolution) {
      // Resolved here and nowhere in the answer. The caller still learns nothing, and the person
      // whose account was attempted can see the attempt in their own trail, which is the point.
      const attempted = await directory.findByLogin(realm.realmId, login);
      await audit.record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authentication',
        action: 'authentication.password',
        outcome: 'failure',
        cause: 'bad_credential',
        correlationId: request.correlationId,
        ...(attempted ? { subjectId: attempted.subjectId } : {}),
        ...(hashIp(request.ip) ? { ipHash: hashIp(request.ip) } : {}),
      });
      return reply.status(401).send(problem(401, 'Authentication failed'));
    }

    const identity = await directory.findBySubjectId(resolution.subjectId);

    // Built by the session service, so a password sign-in and a federated one produce exactly the
    // same session rather than two records that agree today and drift later.
    /**
     * P8.3. A password sign-in resolves through the realm's LOCAL DOMAIN, like any other path.
     *
     * Naming the domain is what makes the concurrent-session limit and the password rules come from
     * the path that did the authenticating, rather than from a branch that only the local case
     * takes. Every realm has one, seeded, so this never resolves to nothing.
     */
    const localDomain = await new RealmService(fastify.db).localDomain(realm.realmId);

    const started = await new SessionService(fastify.db).start({
      realm,
      subjectId: resolution.subjectId,
      epoch: identity?.sessionEpoch ?? 0,
      ...(localDomain ? { domainId: localDomain.providerId } : {}),
      ...(resolution.credentialId ? { credentialId: resolution.credentialId } : {}),
      // The authentication context, so every token minted from this session can carry acr and amr
      // without reading the credential as it stands later.
      acr: resolution.assuranceLevel,
      amr: amrFor(resolution.method),
      ...(request.headers['user-agent'] ? { userAgentHash: hashIp(String(request.headers['user-agent'])) as string } : {}),
      ...(request.ip ? { ipHash: hashIp(request.ip) as string } : {}),
    });

    // The limit was already reached and this path refuses rather than evicting. Recorded as a
    // refusal, because a sign-in that did not happen is exactly what a trail has to show.
    if (isSessionLimitRefusal(started)) {
      await audit.record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authentication',
        action: 'authentication.password',
        outcome: 'failure',
        cause: 'concurrent_session_limit',
        subjectId: resolution.subjectId,
        correlationId: request.correlationId,
        ...(hashIp(request.ip) ? { ipHash: hashIp(request.ip) } : {}),
        detail: { limit: started.limit, held: started.held },
      });
      return reply.status(429).send(problem(
        429,
        'Too many sessions',
        `${started.reason}. Sign out elsewhere, then try again.`,
      ));
    }
    const session = started;

    await audit.record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authentication',
      action: 'authentication.password',
      outcome: 'success',
      subjectId: resolution.subjectId,
      correlationId: request.correlationId,
      ...(hashIp(request.ip) ? { ipHash: hashIp(request.ip) } : {}),
      target: { type: 'session', ref: session.sessionId },
      detail: { method: resolution.method, assuranceLevel: resolution.assuranceLevel },
    });

    return reply.send({
      subjectId: resolution.subjectId,
      sessionId: session.sessionId,
      userName: identity?.userName,
      // So the console can greet somebody by name without waiting for the profile read. The access
      // token deliberately carries no profile claim, so without this every header rendered a login.
      ...(identity?.name?.formatted ? { displayName: identity.name.formatted } : {}),
      assuranceLevel: resolution.assuranceLevel,
      method: resolution.method,
      sessionEpoch: session.epoch,
    });
  });
}

/** Hashed, never raw: an audit record and a session are not places to accumulate personal data. */
function hashIp(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return createHash('sha256').update(value).digest('hex').slice(0, 32);
}
