import { FastifyRequest, FastifyReply } from 'fastify';
import { Db } from 'mongodb';
import { JwtTokenFormat } from '../../modules/oauth/services/jwtTokenFormat';
import { KeyRing } from '../../modules/keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../modules/keys/services/signingKeyStore';
import { RealmService } from '../../modules/realm/services/realm.service';
import { CLIENT_COLLECTION } from '../../shared/models/collections';
import { ClientRecord } from '../../modules/oauth/models/client.model';

/**
 * Who is calling, on the routes the authority serves to a principal rather than to a client.
 *
 * The authority is not a resource server for one audience, so the audience check that a relying party
 * performs has no single value here. What is checked instead is that the token names a client
 * REGISTERED IN THIS REALM: it still proves this authority minted the token for something it knows,
 * which is the meaningful part, and it is stated rather than quietly skipped.
 */

export interface CallingPrincipal {
  subjectId: string;
  realmId: string;
  clientId: string;
  scope: string[];
  sessionId?: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    principal?: CallingPrincipal;
  }
}

export async function resolvePrincipal(
  db: Db,
  realmName: string,
  authorization: string | undefined,
): Promise<CallingPrincipal | null> {
  const token = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token) return null;

  const realm = await new RealmService(db).byName(realmName);
  if (!realm || !realm.enabled) return null;

  const format = new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(db)), realm.realmId);
  const unverified = await format.inspect(token);
  const audience = Array.isArray(unverified?.aud) ? unverified?.aud[0] : unverified?.aud;
  if (typeof audience !== 'string') return null;

  const claims = await format.verify(token, { issuer: realm.issuer, audience });
  if (!claims || typeof claims.sub !== 'string') return null;

  const clientId = typeof claims.client_id === 'string' ? claims.client_id : audience;
  const client = await db.collection<ClientRecord>(CLIENT_COLLECTION)
    .findOne({ realmId: realm.realmId, clientId, status: 'active' }, { projection: { _id: 0, clientId: 1 } });
  if (!client) return null;

  return {
    subjectId: claims.sub,
    realmId: realm.realmId,
    clientId,
    scope: typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [],
    ...(typeof claims.sid === 'string' ? { sessionId: claims.sid } : {}),
  };
}

/** Refuses with the OAuth error object, because these routes sit on the specification's surface. */
export async function requirePrincipal(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const { realm } = request.params as { realm?: string };
  const principal = realm ? await resolvePrincipal(request.server.db, realm, request.headers.authorization) : null;
  if (!principal) {
    return reply.status(401).send({
      error: 'invalid_token',
      error_description: 'A valid access token for this realm is required.',
    });
  }
  request.principal = principal;
}
