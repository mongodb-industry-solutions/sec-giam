import { FastifyInstance } from 'fastify';
import { createHmac } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { SessionService } from '../services/session.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { JwtTokenFormat } from '../../oauth/services/jwtTokenFormat';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { ClientRecord } from '../../oauth/models/client.model';
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

  /**
   * A logout token, signed by the realm.
   *
   * The receiving application verifies it against the same published key set it already uses for
   * access tokens, so single logout introduces no new trust relationship and no new secret.
   */
  async function logoutToken(realmIssuer: string, realmId: string, audience: string, subjectId: string, sessionId: string): Promise<string> {
    const format = new JwtTokenFormat(ring(), realmId, 'logout+jwt');
    const kid = await ring().signingKid(realmId);
    const now = Math.floor(Date.now() / 1000);
    return format.issue({
      iss: realmIssuer,
      aud: audience,
      sub: subjectId,
      iat: now,
      // Short: a logout notification is acted on immediately or it is stale.
      exp: now + 120,
      sid: sessionId,
      // The member that says this is a logout and not something else the authority signed.
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      jti: createHmac('sha256', sessionId).update(String(now)).digest('hex').slice(0, 32),
    }, kid);
  }

  /**
   * Delivers to each client, and never lets a delivery failure undo the logout.
   *
   * A receiver that is down must not keep a session alive. The bound on that case is the access
   * token lifetime, which is short, and the revocation is already recorded here regardless.
   */
  async function notify(clients: ClientRecord[], realmIssuer: string, realmId: string, subjectId: string, sessionId: string) {
    const delivered: string[] = [];
    const failed: string[] = [];

    await Promise.all(clients.map(async (client) => {
      const endpoint = client.backchannel?.notificationEndpoint;
      if (!endpoint) return;
      try {
        const token = await logoutToken(realmIssuer, realmId, client.clientId, subjectId, sessionId);
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ logout_token: token }),
          signal: AbortSignal.timeout(3000),
        });
        (response.ok ? delivered : failed).push(client.clientId);
      } catch {
        failed.push(client.clientId);
      }
    }));

    return { delivered, failed };
  }

  fastify.post('/realms/:realm/protocol/openid-connect/logout', {
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
          post_logout_redirect_uri: { type: 'string' },
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
        400: { $ref: 'Problem#', description: 'Neither a session nor a subject was named.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as { session_id?: string; subject_id?: string; post_logout_redirect_uri?: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const sessions = new SessionService(fastify.db);
    const issuer = new TokenIssuer(fastify.db, ring());
    const audit = new SecurityEventService(fastify.db);

    if (body.subject_id) {
      const outcome = await sessions.terminateAllFor(realm.realmId, body.subject_id, 'logout', issuer);
      const notified = await notify(outcome.notify, realm.issuer, realm.realmId, body.subject_id, 'all');

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
        ...(body.post_logout_redirect_uri ? { post_logout_redirect_uri: body.post_logout_redirect_uri } : {}),
      });
    }

    if (!body.session_id) {
      return reply.status(400).send(problem(400, 'Either session_id or subject_id is required'));
    }

    const session = await sessions.find(realm.realmId, body.session_id);
    const outcome = await sessions.terminate(realm.realmId, body.session_id, 'logout', issuer);
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

    // 200 whether or not a session was found, for the same reason revocation does: reporting "no
    // such session" would confirm which session identifiers are real.
    return reply.send({
      sessions: outcome.terminated ? 1 : 0,
      revokedTokens: outcome.revokedTokens,
      notified: notified.delivered,
      notificationFailures: notified.failed,
      ...(body.post_logout_redirect_uri ? { post_logout_redirect_uri: body.post_logout_redirect_uri } : {}),
    });
  });
}
