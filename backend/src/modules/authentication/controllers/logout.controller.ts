import { FastifyInstance } from 'fastify';
import { clearSessionCookie, readSessionCookie } from '../services/sessionCookie';
import { RealmService } from '../../realm/services/realm.service';
import { SessionService } from '../services/session.service';
import { LogoutNotifier } from '../services/logoutNotifier.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { OAuthClient } from '../../oauth/models/client.model';
import { findOAuthClient } from '../../oauth/services/clientAuth.service';
import { JwtTokenFormat } from '../../oauth/services/jwtTokenFormat';
import { problem } from '../../../shared/models/problem';

/**
 * Logout, and the notifications that make it single sign-out.
 *
 * Ending a session locally would leave every application still holding a valid token, so the
 * operation only means something if the other applications hear about it. Back-channel notification
 * is what turns "signed out here" into "signed out everywhere", and it is delivered as a signed
 * token so a receiver can tell a real notification from anyone who learned a session id.
 */
export async function logoutController(fastify: FastifyInstance) {
  const ring = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  // Signing and delivering the notification is the same act wherever a session ends, so it lives in
  // one service that the administrative session routes use too.
  const notify = (clients: OAuthClient[], realmIssuer: string, realmId: string, subjectId: string, sessionId: string) =>
    new LogoutNotifier(fastify.db).notify(clients, { issuer: realmIssuer, realmId }, subjectId, sessionId);

  /**
   * WHICH client is asking to sign out, from what the standard provides for saying so.
   *
   * `id_token_hint` first, because it is evidence rather than a claim: this authority signed it, so
   * the `aud` inside it cannot be changed to name a client the caller is not. An explicit
   * `client_id` is accepted on its own as the standard allows, and when both arrive they must agree,
   * since a mismatch is either a mistake or an attempt to borrow another client's registration.
   *
   * Returns undefined when neither was sent. The caller then honours no redirect at all, which is
   * what RP-Initiated Logout 1.0 requires: without knowing the client, there is no registration to
   * verify a return address against.
   */
  async function requestingClient(
    realm: { realmId: string; issuer: string },
    body: { client_id?: string; id_token_hint?: string },
  ): Promise<string | undefined> {
    if (!body.id_token_hint) return body.client_id;

    // `JWT`, the type an ID token is signed with here, so an access or refresh token cannot stand in
    // for one. The audience has to be read before it can be checked, which is not circular: a forged
    // audience does not survive the signature check below.
    const format = new JwtTokenFormat(ring(), realm.realmId, 'JWT');
    const unverified = await format.inspect(body.id_token_hint);
    const audience = Array.isArray(unverified?.aud) ? unverified?.aud[0] : unverified?.aud;
    if (typeof audience !== 'string' || !audience) return undefined;

    const claims = await format.verify(
      body.id_token_hint,
      { issuer: realm.issuer, audience },
      // An expired hint still identifies the client. See the note on `verify`.
      { allowExpired: true },
    );
    if (!claims) return undefined;
    // `azp` when the token was issued for a party other than its audience; otherwise the audience is
    // the client. Both are the same value here, and reading azp first keeps that an implementation
    // detail of issuance rather than something this check depends on.
    const party = typeof claims.azp === 'string' ? claims.azp : audience;
    if (body.client_id && body.client_id !== party) return undefined;
    return party;
  }

  /**
   * A return address the REQUESTING client registered, and no one else's.
   *
   * It used to be any URI any client in the realm had registered, which is a closed list and so not
   * an open redirect, but it let one application end a session and send the browser to another
   * application's address. Each client declares where it wants to land and is held to its own
   * declaration, which is both what the standard says and the only version that is a boundary
   * rather than a shared pool.
   */
  async function registeredLogoutRedirect(
    realmId: string,
    uri: string | undefined,
    clientId: string | undefined,
  ): Promise<string | undefined> {
    if (!uri || !clientId) return undefined;
    let canonical: string;
    try {
      canonical = new URL(uri).toString();
    } catch {
      return undefined;
    }
    const client = await findOAuthClient(fastify.db, realmId, clientId);
    const registered = client?.postLogoutRedirectUris?.some((declared) => {
      try {
        return new URL(declared).toString() === canonical;
      } catch {
        return false;
      }
    });
    return registered ? uri : undefined;
  }

  fastify.post('/realms/:realm/protocol/oidc/logout', {
    schema: {
      operationId: 'endSession',
      tags: ['authentication'],
      summary: 'End a session',
      description:
        'Standard-defined: OpenID Connect RP-Initiated Logout 1.0 and Back-Channel Logout 1.0. Ends '
        + 'the session, revokes what was issued under it, raises the principal session epoch so any '
        + 'unrecorded token is retired too, and notifies every client that holds one. A delivery '
        + 'failure never undoes the logout: a receiver that is down must not keep a session alive.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          session_id: { type: 'string', description: 'The session to end.' },
          subject_id: { type: 'string', description: 'Ends EVERY session this principal holds.' },
          post_logout_redirect_uri: {
            type: 'string',
            description:
              'Honoured only when the REQUESTING client declares it in its own postLogoutRedirectUris, '
              + 'which means one of id_token_hint or client_id must identify that client.',
          },
          id_token_hint: {
            type: 'string',
            description:
              'An ID token this authority issued to the client that is signing out. Preferred over '
              + 'client_id: it is signed, so the client it names cannot be substituted. An expired '
              + 'one is accepted.',
          },
          client_id: {
            type: 'string',
            description: 'The client that is signing out, when no id_token_hint is sent.',
          },
        },
      },
      response: {
        200: {
          description: 'What was ended and who was told.',
          type: 'object',
          additionalProperties: false,
          required: ['sessions', 'revokedTokens'],
          properties: {
            sessions: { type: 'integer' },
            revokedTokens: { type: 'integer' },
            notified: { type: 'array', items: { type: 'string' } },
            notificationFailures: { type: 'array', items: { type: 'string' } },
            post_logout_redirect_uri: { type: 'string' },
          },
          examples: [{ sessions: 1, revokedTokens: 3, notified: ['orders-web'], notificationFailures: [] }],
        },
        400: { $ref: 'Problem#', description: 'No session was named, and the browser holds no session cookie either.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as {
      session_id?: string; subject_id?: string; post_logout_redirect_uri?: string;
      id_token_hint?: string; client_id?: string;
    };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const sessions = new SessionService(fastify.db);
    const issuer = new TokenIssuer(fastify.db, ring());
    const audit = new SecurityEventService(fastify.db);

    if (body.subject_id) {
      const outcome = await sessions.terminateAllFor(realm.realmId, body.subject_id, 'logout', issuer);
      const notified = await notify(outcome.notify, realm.issuer, realm.realmId, body.subject_id, 'all');
      const redirect = await registeredLogoutRedirect(
        realm.realmId, body.post_logout_redirect_uri, await requestingClient(realm, body),
      );

      await audit.record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        action: 'authentication.logout.all',
        outcome: 'success',
        category: 'session',
        subjectId: body.subject_id,
        detail: { sessions: outcome.sessions, revokedTokens: outcome.revokedTokens },
      });

      return reply.send({
        sessions: outcome.sessions,
        revokedTokens: outcome.revokedTokens,
        notified: notified.delivered,
        notificationFailures: notified.failed,
        ...(redirect ? { post_logout_redirect_uri: redirect } : {}),
      });
    }

    // The CURRENT session, from the cookie, when nothing else was named: a relying party's sign-in
    // gives the browser no session id to remember, only the cookie.
    const sessionId = body.session_id ?? readSessionCookie(request);
    if (!sessionId) {
      return reply.status(400).send(problem(400, 'No session was named, and the browser holds no session cookie either'));
    }

    const session = await sessions.find(realm.realmId, sessionId);
    const outcome = await sessions.terminate(realm.realmId, sessionId, 'logout', issuer);
    const notified = session
      ? await notify(outcome.notify, realm.issuer, realm.realmId, session.subjectId, session.sessionId)
      : { delivered: [], failed: [] };

    await audit.record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      action: 'authentication.logout',
      outcome: 'success',
      category: 'session',
      subjectId: session?.subjectId,
      detail: { revokedTokens: outcome.revokedTokens },
    });

    /**
     * The cookie goes with the session, unconditionally.
     *
     * Cleared even when no session was found, which follows from the line below: the answer must not
     * differ on whether the session existed, and neither must the headers. Leaving a stale cookie
     * behind would also mean the next authorization attempt presents an identifier that resolves to
     * nothing, which reads as an expiry rather than as a sign-out.
     */
    clearSessionCookie(request, reply);
    const redirect = await registeredLogoutRedirect(
      realm.realmId, body.post_logout_redirect_uri, await requestingClient(realm, body),
    );

    // 200 whether or not a session was found, for the same reason revocation does: reporting "no
    // such session" would confirm which session identifiers are real.
    return reply.send({
      sessions: outcome.terminated ? 1 : 0,
      revokedTokens: outcome.revokedTokens,
      notified: notified.delivered,
      notificationFailures: notified.failed,
      ...(redirect ? { post_logout_redirect_uri: redirect } : {}),
    });
  });
}
