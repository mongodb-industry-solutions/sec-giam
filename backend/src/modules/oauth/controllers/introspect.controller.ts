import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, readClientCredentials } from '../services/clientAuth.service';
import { TokenIssuer } from '../services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { JwtTokenFormat } from '../services/jwtTokenFormat';
import { DirectoryService } from '../../directory/services/directory.service';
import { canAuthenticate } from '../../directory/models/principal.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { oauthError } from '../../../shared/models/problem';
import { RESOURCE_COLLECTION } from '../../../shared/models/collections';

/**
 * Introspection and revocation: the centralised half of token validation.
 *
 * Local verification answers "was this signed by the authority and is it still within its lifetime".
 * Introspection answers "is this ACTIVE right now", which is a different question: it accounts for
 * revocation, for a suspended principal and for permissions that changed since issuance. Neither is
 * right in general, which is why both exist and the resource server chooses per operation.
 *
 * The cost is real and stated: a network round trip, and the authority on the hot path of whatever
 * calls it. That is why the recommendation is to verify locally by default and introspect only where
 * being wrong is expensive to undo.
 */
export async function introspectController(fastify: FastifyInstance) {
  const ring = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  fastify.post('/realms/:realm/protocol/openid-connect/token/introspect', {
    schema: {
      operationId: 'introspectToken',
      tags: ['oauth'],
      summary: 'Token introspection',
      description:
        'Standard-defined: RFC 7662. Answers whether a token is ACTIVE now, which local verification '
        + 'cannot: it accounts for revocation, for a suspended principal and for permissions that '
        + 'changed since issuance. Form encoded, and the caller authenticates as its own client, '
        + 'because an unauthenticated introspection endpoint is an oracle for token validity.',
      security: [{ clientBasic: [] }],
      consumes: ['application/x-www-form-urlencoded'],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['token'],
        additionalProperties: true,
        properties: {
          token: { type: 'string' },
          token_type_hint: { type: 'string', enum: ['access_token', 'refresh_token'] },
          client_id: { type: 'string' },
          client_secret: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'The introspection response. `active: false` is the only guaranteed member.',
          type: 'object',
          additionalProperties: true,
          required: ['active'],
          properties: {
            active: { type: 'boolean' },
            scope: { type: 'string' },
            client_id: { type: 'string' },
            sub: { type: 'string' },
            exp: { type: 'integer' },
            iat: { type: 'integer' },
            token_type: { type: 'string' },
            entitlements: { type: 'array', items: { type: 'string' } },
          },
          examples: [{ active: true, sub: 'ada', client_id: 'orders-web', scope: 'openid profile' }],
        },
        401: { $ref: 'OAuthError#', description: 'Client authentication failed.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as Record<string, unknown>;

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(401).send(oauthError('invalid_client', 'unknown realm', 401));

    const clientAuth = new ClientAuthService(fastify.db);
    const outcome = await clientAuth.authenticate(
      realm,
      readClientCredentials(request.headers.authorization, body),
      // No soft admission on a privileged surface. Onboarding explains an unregistered consumer at
      // the token endpoint; it explains nothing here.
      { requireAuthentication: true, allowSoftAdmission: false },
    );
    if ('error' in outcome) return reply.status(401).send(oauthError('invalid_client', outcome.description, 401));

    /**
     * Every negative answer is the same answer.
     *
     * RFC 7662 says an inactive token returns `{active: false}` and nothing else, and that is not a
     * formality: distinguishing "expired" from "revoked" from "never existed" tells a caller holding
     * a stolen token which of those it is holding.
     */
    const inactive = { active: false };
    const presented = String(body.token ?? '');
    if (!presented) return reply.send(inactive);

    const format = new JwtTokenFormat(ring(), realm.realmId);
    const claims = await format.verify(presented, {
      issuer: realm.issuer,
      audience: String(claimsAudience(await format.inspect(presented)) ?? ''),
    });
    if (!claims) return reply.send(inactive);

    /**
     * Introspection is recorded only when the answer is no.
     *
     * A resource server introspecting a valid token does it on every request it serves, and the fact
     * it establishes is already in the issuance record. Writing one event per call would bury the
     * events that matter under the ones that do not. A REFUSED introspection is the opposite: a token
     * that was revoked or whose principal was retired is still being presented by somebody, and that
     * is worth seeing exactly once per occurrence.
     */
    const refused = (cause: string, subject?: unknown) => {
      void new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        action: 'oauth.token.introspected',
        outcome: 'failure',
        category: 'token',
        cause,
        clientId: outcome.client.clientId,
        ...(typeof subject === 'string' ? { subjectId: subject } : {}),
        correlationId: request.correlationId,
      });
      return reply.send(inactive);
    };

    const issuer = new TokenIssuer(fastify.db, ring());

    /**
     * P6.8. The authoritative part answers from the SESSION, not from a stored token.
     *
     * A signature says the token was issued; the session says whether access is still live. That is
     * the same question the old token row answered, asked of one document per session instead of one
     * per token, and the absence of that document IS the revocation.
     *
     * A token with no `sid` carries no session by design: `client_credentials` creates none. Such a
     * token is active for as long as its signature and expiry say, because there is nothing to
     * revoke and pretending otherwise would make introspection lie.
     */
    const sid = typeof claims.sid === 'string' ? claims.sid : undefined;
    if (sid) {
      const live = await issuer.sessionIsLive(realm.realmId, sid);
      if (!live) return refused('session_revoked', claims.sub);
    }

    /**
     * A caller may introspect only tokens addressed to it. Otherwise introspection becomes a way for
     * any registered client to read the claims of anyone else's token.
     *
     * "Addressed to it" now means the RESOURCE SERVER, because that is what an audience names since
     * the issuer was corrected to RFC 9068. A client introspecting its own token still matches by
     * client id, which is the case a confidential client checking what it holds.
     *
     * This is a realm-wide boundary rather than a per-client one, and that is stated rather than
     * glossed: within a realm, every registered resource server can introspect tokens issued for
     * that realm's protected API. Narrowing it further requires each caller to declare which
     * resource server it IS, which is a registration change and belongs with one.
     */
    const audience = (Array.isArray(claims.aud) ? claims.aud : [claims.aud]).map(String);
    const servers = await fastify.db
      .collection<{ audience: string }>(RESOURCE_COLLECTION)
      .find({ realmId: realm.realmId }, { projection: { _id: 0, audience: 1 } })
      .toArray();
    const addressable = new Set([outcome.client.clientId, ...servers.map((server) => server.audience)]);
    if (!audience.some((entry) => addressable.has(entry))) return reply.send(inactive);

    // Current status, not status at issuance. This is the whole reason to ask.
    // A machine token's `sub` is its own owning principal, so comparing against the presenting
    // client's id is what tells a person's token apart from a service's without a stored row.
    if (claims.sub && claims.sub !== claims.client_id) {
      const identity = await new DirectoryService(fastify.db).findBySubjectId(String(claims.sub));
      if (!identity || !canAuthenticate(identity)) return refused('subject_cannot_authenticate', claims.sub);
      if (typeof claims.session_epoch === 'number' && claims.session_epoch < identity.sessionEpoch) {
        return refused('session_epoch_raised', claims.sub);
      }
    }

    return reply.send({
      active: true,
      scope: claims.scope,
      client_id: claims.client_id,
      sub: claims.sub,
      exp: claims.exp,
      iat: claims.iat,
      token_type: 'Bearer',
      ...(claims.entitlements ? { entitlements: claims.entitlements } : {}),
    });
  });

  fastify.post('/realms/:realm/protocol/openid-connect/revoke', {
    schema: {
      operationId: 'revokeToken',
      tags: ['oauth'],
      summary: 'Token revocation',
      description:
        'Standard-defined: RFC 7009. Answers 200 whether or not the token existed, per section 2.2, '
        + 'because a revocation endpoint that reported "no such token" would tell a caller which of '
        + 'the tokens it holds are real.',
      security: [{ clientBasic: [] }],
      consumes: ['application/x-www-form-urlencoded'],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['token'],
        additionalProperties: true,
        properties: {
          token: { type: 'string' },
          token_type_hint: { type: 'string' },
          client_id: { type: 'string' },
          client_secret: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'Accepted. Deliberately identical whether or not anything was revoked.',
          type: 'object',
          additionalProperties: false,
          properties: { revoked: { type: 'boolean' } },
          examples: [{ revoked: true }],
        },
        401: { $ref: 'OAuthError#', description: 'Client authentication failed.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as Record<string, unknown>;

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(401).send(oauthError('invalid_client', 'unknown realm', 401));

    const clientAuth = new ClientAuthService(fastify.db);
    const outcome = await clientAuth.authenticate(
      realm,
      readClientCredentials(request.headers.authorization, body),
      // No soft admission on a privileged surface. Onboarding explains an unregistered consumer at
      // the token endpoint; it explains nothing here.
      { requireAuthentication: true, allowSoftAdmission: false },
    );
    if ('error' in outcome) return reply.status(401).send(oauthError('invalid_client', outcome.description, 401));

    const issuer = new TokenIssuer(fastify.db, ring());
    const presented = String(body.token ?? '');
    let revoked = false;

    /**
     * RFC 7009. Revoking a token means DELETING THE SESSION it belongs to.
     *
     * Both token kinds are JWTs now and both carry `sid`, so one path handles them and a client
     * does not have to know which it holds. The session is what access depends on, so removing it
     * is what "revoked" can honestly mean: there is no stored token to mark.
     *
     * Accepted and stated: the presented access token keeps verifying until it expires, because it
     * is verified without touching the database. With a five minute lifetime that window is the
     * revocation objective, and no design that verifies locally can do better.
     *
     * The subject is carried out so the event names the person the token was for, not only the
     * client that asked.
     */
    let subjectId: string | undefined;

    const claims = await new JwtTokenFormat(ring(), realm.realmId).inspect(presented);
    const sid = claims && typeof claims.sid === 'string' ? claims.sid : undefined;
    const tokenClientId = claims && typeof claims.client_id === 'string' ? claims.client_id : undefined;
    if (sid && tokenClientId === outcome.client.clientId) {
      subjectId = typeof claims?.sub === 'string' ? claims.sub : undefined;
      revoked = (await issuer.revokeSession(realm.realmId, sid)) > 0;
    }

    if (revoked) {
      await new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        action: 'oauth.token.revoked',
        outcome: 'success',
        category: 'token',
        clientId: outcome.client.clientId,
        ...(subjectId ? { subjectId } : {}),
        correlationId: request.correlationId,
      });
    }

    return reply.send({ revoked });
  });
}

/** The audience a token claims, so verification can be asked to check the right one. */
function claimsAudience(claims: Record<string, unknown> | null): string | undefined {
  if (!claims) return undefined;
  const audience = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
  return typeof audience === 'string' ? audience : undefined;
}
