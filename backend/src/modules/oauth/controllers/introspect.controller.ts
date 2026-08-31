import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, readClientCredentials } from '../services/clientAuth.service';
import { TokenIssuer } from '../services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { JwtTokenFormat } from '../services/jwtTokenFormat';
import { DirectoryService } from '../../directory/services/directory.service';
import { canAuthenticate } from '../../directory/models/identity.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { oauthError } from '../../../shared/models/problem';
import { RESOURCE_SERVER_COLLECTION } from '../../../shared/models/collections';

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
            permissions: { type: 'array', items: { type: 'object', additionalProperties: true } },
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
    if (!realm) return reply.status(401).send(oauthError(401, 'unknown realm'));

    const clientAuth = new ClientAuthService(fastify.db);
    const outcome = await clientAuth.authenticate(
      realm.realmId,
      readClientCredentials(request.headers.authorization, body),
      { requireAuthentication: true },
    );
    if ('error' in outcome) return reply.status(401).send(oauthError(401, outcome.description));

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

    const issuer = new TokenIssuer(fastify.db, ring());
    const record = typeof claims.jti === 'string' ? await issuer.findByJti(realm.realmId, claims.jti) : null;
    // The authoritative part: a signature says it was issued, the record says whether it still counts.
    if (!record || record.revokedAt) return reply.send(inactive);

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
      .collection<{ audience: string }>(RESOURCE_SERVER_COLLECTION)
      .find({ realmId: realm.realmId }, { projection: { _id: 0, audience: 1 } })
      .toArray();
    const addressable = new Set([outcome.client.clientId, ...servers.map((server) => server.audience)]);
    if (!audience.some((entry) => addressable.has(entry))) return reply.send(inactive);

    // Current status, not status at issuance. This is the whole reason to ask.
    if (claims.sub && claims.sub !== record.clientId) {
      const identity = await new DirectoryService(fastify.db).findBySubjectId(String(claims.sub));
      if (!identity || !canAuthenticate(identity)) return reply.send(inactive);
      if (typeof claims.session_epoch === 'number' && claims.session_epoch < identity.sessionEpoch) {
        return reply.send(inactive);
      }
    }

    await new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      action: 'oauth.token.introspected',
      outcome: 'success',
      category: 'token',
      clientId: outcome.client.clientId,
      subjectId: typeof claims.sub === 'string' ? claims.sub : undefined,
    });

    return reply.send({
      active: true,
      scope: claims.scope,
      client_id: claims.client_id,
      sub: claims.sub,
      exp: claims.exp,
      iat: claims.iat,
      token_type: 'Bearer',
      ...(claims.permissions ? { permissions: claims.permissions } : {}),
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
    if (!realm) return reply.status(401).send(oauthError(401, 'unknown realm'));

    const clientAuth = new ClientAuthService(fastify.db);
    const outcome = await clientAuth.authenticate(
      realm.realmId,
      readClientCredentials(request.headers.authorization, body),
      { requireAuthentication: true },
    );
    if ('error' in outcome) return reply.status(401).send(oauthError(401, outcome.description));

    const issuer = new TokenIssuer(fastify.db, ring());
    const presented = String(body.token ?? '');
    let revoked = false;

    // A refresh token is opaque and carries its identifier; an access token is a JWT and carries it
    // as a claim. Both are accepted, because a client should not have to know which it holds.
    const asRefresh = await issuer.findRefreshToken(realm.realmId, presented);
    if (asRefresh && asRefresh.clientId === outcome.client.clientId) {
      revoked = await issuer.revoke(realm.realmId, asRefresh.jti, 'client_requested');
    } else {
      const claims = await new JwtTokenFormat(ring(), realm.realmId).inspect(presented);
      if (claims && typeof claims.jti === 'string') {
        const record = await issuer.findByJti(realm.realmId, claims.jti);
        if (record && record.clientId === outcome.client.clientId) {
          revoked = await issuer.revoke(realm.realmId, record.jti, 'client_requested');
        }
      }
    }

    if (revoked) {
      await new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        action: 'oauth.token.revoked',
        outcome: 'success',
        category: 'token',
        clientId: outcome.client.clientId,
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
