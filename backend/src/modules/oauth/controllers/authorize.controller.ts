import { FastifyInstance } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { createHash, randomBytes } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService } from '../services/clientAuth.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { AUTHORIZATION_REQUEST_COLLECTION, SESSION_COLLECTION } from '../../../shared/models/collections';
import { AuthorizationRequestRecord } from '../models/authorizationRequest.model';
import { SessionRecord, isLive } from '../../authentication/models/session.model';
import { scopesOf } from '../models/client.model';
import { newMeta } from '../../../shared/models/base.model';
import { oauthError } from '../../../shared/models/problem';

/**
 * The authorization endpoint, RFC 6749 §4.1 with PKCE.
 *
 * Exchanges an established session for a one-time code. The session is what the sign-in produced;
 * this turns it into something a specific client can redeem exactly once, for a specific redirect,
 * with a specific proof.
 *
 * Deliberately NOT a place that accepts credentials. A client sends a browser here and gets a code
 * back; if there is no session, the answer is that one is needed, never a prompt this endpoint
 * handles itself. Keeping credential entry in one place is the whole reason the authority exists.
 */
export async function authorizeController(fastify: FastifyInstance) {
  fastify.post('/realms/:realm/protocol/openid-connect/auth', {
    schema: {
      operationId: 'authorize',
      tags: ['oauth'],
      summary: 'Authorization endpoint',
      description:
        'Standard-defined: RFC 6749 section 4.1 and RFC 7636 (PKCE). Exchanges an established '
        + 'session for a single-use authorization code bound to the client, the redirect URI and the '
        + 'PKCE challenge. It never accepts a credential: a request with no session is told one is '
        + 'required rather than being prompted here.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['client_id', 'redirect_uri', 'response_type', 'session_id'],
        additionalProperties: false,
        properties: {
          client_id: { type: 'string', examples: ['orders-web'] },
          redirect_uri: { type: 'string', examples: ['https://app.example/callback'] },
          response_type: { type: 'string', enum: ['code'] },
          scope: { type: 'string', examples: ['openid profile'] },
          state: { type: 'string' },
          nonce: { type: 'string' },
          code_challenge: { type: 'string' },
          code_challenge_method: { type: 'string', enum: ['S256'] },
          session_id: { type: 'string', description: 'The session established at sign-in.' },
        },
      },
      response: {
        200: {
          description: 'The authorization code, and the state to echo back.',
          type: 'object',
          additionalProperties: false,
          required: ['code', 'redirect_uri'],
          properties: {
            code: { type: 'string' },
            state: { type: 'string' },
            redirect_uri: { type: 'string' },
          },
          examples: [{ code: 'a1b2…', state: 'xyz', redirect_uri: 'https://app.example/callback' }],
        },
        400: { $ref: 'OAuthError#', description: 'The request is invalid or the scope is not permitted.' },
        401: { $ref: 'OAuthError#', description: 'No live session.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as {
      client_id: string;
      redirect_uri: string;
      response_type: string;
      scope?: string;
      state?: string;
      nonce?: string;
      code_challenge?: string;
      code_challenge_method?: 'S256';
      session_id: string;
    };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm || !realm.enabled) return reply.status(400).send(oauthError(400, 'unknown realm'));

    const client = await new ClientAuthService(fastify.db).find(realm.realmId, body.client_id);
    if (!client || client.status !== 'active') {
      return reply.status(400).send(oauthError(400, 'unknown client'));
    }

    // Exact match, never a prefix. A redirect URI compared loosely is how an authorization code ends
    // up delivered to an attacker's path on a legitimate host.
    if (!client.redirectUris.includes(body.redirect_uri)) {
      return reply.status(400).send(oauthError(400, 'redirect_uri is not registered for this client'));
    }

    if (client.requirePkce && !body.code_challenge) {
      return reply.status(400).send(oauthError(400, 'this client requires PKCE'));
    }

    const requested = (body.scope ?? 'openid').split(' ').filter(Boolean);
    const permitted = scopesOf(client);
    const refused = requested.filter((scope) => !permitted.includes(scope));
    // Refused rather than narrowed. Silently dropping a scope means the client believes it holds
    // authority it does not, and discovers otherwise at the point of use.
    if (refused.length > 0) {
      return reply.status(400).send(oauthError(400, `scope not permitted: ${refused.join(' ')}`));
    }

    const session = await fastify.db
      .collection<SessionRecord>(SESSION_COLLECTION)
      .findOne({ realmId: realm.realmId, sessionId: body.session_id }, { projection: { _id: 0 } });
    if (!session || !isLive(session)) {
      return reply.status(401).send(oauthError(401, 'no live session'));
    }

    const identity = await new DirectoryService(fastify.db).findBySubjectId(session.subjectId);
    if (!identity) return reply.status(401).send(oauthError(401, 'no live session'));

    const code = randomBytes(32).toString('base64url');
    const now = new Date();
    const record: AuthorizationRequestRecord = {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      requestId: uuidv4(),
      flow: 'authorization_code',
      clientId: client.clientId,
      subjectId: identity.subjectId,
      status: 'approved',
      // Hashed at rest, for the same reason a password is: reading this collection must not leave
      // anyone able to redeem an outstanding authorization.
      codeHash: createHash('sha256').update(code).digest('hex'),
      ...(body.code_challenge
        ? { pkce: { challenge: body.code_challenge, method: body.code_challenge_method ?? 'S256' } }
        : {}),
      redirectUri: body.redirect_uri,
      ...(body.state ? { state: body.state, stateHash: createHash('sha256').update(body.state).digest('hex').slice(0, 16) } : {}),
      ...(body.nonce ? { nonce: body.nonce } : {}),
      scope: requested.join(' '),
      attemptCount: 0,
      // Short by design: a code is a bearer credential in a URL, and its window should be the time a
      // browser needs to complete one redirect, not the time a person needs to read a page.
      expiresAt: new Date(now.getTime() + realm.tokenPolicy.codeTtlSeconds * 1000).toISOString(),
      meta: newMeta('AuthorizationRequest'),
    };
    await fastify.db.collection<AuthorizationRequestRecord>(AUTHORIZATION_REQUEST_COLLECTION).insertOne(record);

    // The session now knows which clients hold tokens from it, so a logout can notify each of them.
    await fastify.db.collection<SessionRecord>(SESSION_COLLECTION).updateOne(
      { sessionId: session.sessionId },
      { $addToSet: { clientIds: client.clientId }, $set: { lastSeenAt: now.toISOString() } },
    );

    return reply.send({
      code,
      ...(body.state ? { state: body.state } : {}),
      redirect_uri: body.redirect_uri,
    });
  });
}
