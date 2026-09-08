import { FastifyRequest, FastifyReply } from 'fastify';
import { Db } from 'mongodb';
import { JwtTokenFormat } from '../../modules/oauth/services/jwtTokenFormat';
import { KeyRing } from '../../modules/keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../modules/keys/services/signingKeyStore';
import { RealmService } from '../../modules/realm/services/realm.service';
import { findOAuthClient } from '../../modules/oauth/services/clientAuth.service';
import { OAuthClient } from '../../modules/oauth/models/client.model';
import { DecisionService } from '../../modules/authorization/services/decision.service';
import { SecurityEventService } from '../../modules/audit/services/securityEvent.service';
import { problem } from '../../shared/models/problem';

/**
 * Who is calling, on the routes the authority serves to a principal rather than to a client.
 *
 * The authority is not a resource server for one audience, so the audience check that a relying party
 * performs has no single value here. What is checked instead is that the token names a client
 * REGISTERED IN THIS REALM: it still proves this authority minted the token for something it knows,
 * which is the meaningful part, and it is stated rather than quietly skipped.
 *
 * A token is ALWAYS verified against the keys and issuer of the realm that minted it, and never
 * against another realm's. When somebody administers a second realm, what changes is the realm the
 * request acts on, not the realm that vouches for the token: the signature is checked at home, and
 * the grant that reaches outward is a stored assignment read afterwards.
 */

export interface CallingPrincipal {
  subjectId: string;
  /** The realm this request ACTS on, which is the realm named in the path. */
  realmId: string;
  /** The realm that issued and signed the token. The same as `realmId` unless a grant crosses. */
  homeRealmId: string;
  clientId: string;
  scope: string[];
  sessionId?: string;
  /** True when the caller is reaching into a realm that is not their own. */
  crossRealm: boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal?: CallingPrincipal;
    /**
     * Set when a route expected a bearer token, whether or not one was accepted.
     *
     * This is what tells the `WWW-Authenticate` hook that the route is a PROTECTED RESOURCE. Routing
     * on the URL would not do: `/protocol/openid-connect/userinfo` is a protected resource and needs
     * the challenge, while `/protocol/openid-connect/token` authenticates a client and must not have
     * one, and both live under the same path prefix.
     */
    bearerProtected?: boolean;
  }
}

export async function resolvePrincipal(
  db: Db,
  realmName: string,
  authorization: string | undefined,
): Promise<CallingPrincipal | null> {
  const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return null;

  const realms = new RealmService(db);
  const target = await realms.byName(realmName);
  if (!target || !target.enabled) return null;

  // The issuing realm is taken from the token's own issuer, so verification always happens against
  // the keys of whoever minted it. A token addressed at a realm it did not come from is verified at
  // home and then judged against a stored grant, never verified with the target realm's keys.
  const inspector = new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(db)), target.realmId);
  const unverified = await inspector.inspect(token);
  const issuer = typeof unverified?.iss === 'string' ? unverified.iss : '';
  const home = issuer === target.issuer ? target : await realms.byIssuer(issuer);
  if (!home || !home.enabled) return null;

  const audience = Array.isArray(unverified?.aud) ? unverified?.aud[0] : unverified?.aud;
  if (typeof audience !== 'string') return null;

  const format = new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(db)), home.realmId);
  const claims = await format.verify(token, { issuer: home.issuer, audience });
  if (!claims || typeof claims.sub !== 'string') return null;

  const clientId = typeof claims.client_id === 'string' ? claims.client_id : audience;
  const client = await findOAuthClient(db, home.realmId, clientId);
  if (!client || client.status !== 'active') return null;

  const crossRealm = home.realmId !== target.realmId;
  if (crossRealm) {
    // Admitted only against a grant that names this realm, and recorded either way. A refusal here is
    // somebody reaching across an isolation boundary they do not hold, which is worth a record too.
    const granted = await new DecisionService(db).grantedRealmIds(home.realmId, claims.sub);
    await new SecurityEventService(db).record({
      realmId: target.realmId,
      tenantId: target.tenantId,
      category: 'authorization',
      action: 'authorization.cross_realm_access',
      outcome: granted.includes(target.realmId) ? 'success' : 'failure',
      decision: granted.includes(target.realmId) ? 'allow' : 'deny',
      subjectId: claims.sub,
      clientId,
      // Both realms are named, because the question an auditor asks about a crossing is which two
      // realms it joined, and a record naming one of them cannot answer it.
      detail: { homeRealm: home.name, homeRealmId: home.realmId, targetRealm: target.name, targetRealmId: target.realmId },
      target: { type: 'realm', ref: target.realmId },
    });
    if (!granted.includes(target.realmId)) return null;
  }

  return {
    subjectId: claims.sub,
    realmId: target.realmId,
    homeRealmId: home.realmId,
    clientId,
    crossRealm,
    scope: typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [],
    ...(typeof claims.sid === 'string' ? { sessionId: claims.sid } : {}),
  };
}

/**
 * Refuses with problem details in the body and the RFC 6750 challenge in the header.
 *
 * Marks the request as bearer-protected first, so the challenge is added whether the refusal comes
 * from here or from an authorization check further in.
 */
export async function requirePrincipal(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  request.bearerProtected = true;
  const { realm } = request.params as { realm?: string };
  const principal = realm ? await resolvePrincipal(request.server.db, realm, request.headers.authorization) : null;
  if (!principal) {
    /**
     * Problem details in the BODY, the OAuth code in the `WWW-Authenticate` header.
     *
     * It sent `{error, error_description}` here while every route declared `401: Problem#`, so the
     * response did not match its own published schema. RFC 6750 3 puts the error code in the
     * challenge header rather than the body, which resolves both: the body is the shape this
     * surface promises, and the header is the shape the standard requires. The header itself is
     * added by the `onSend` hook in `app.ts`, so no refusal can forget it.
     */
    return reply.status(401).send(problem(401, 'Unauthorized', 'A valid access token for this realm is required.'));
  }
  request.principal = principal;
}
