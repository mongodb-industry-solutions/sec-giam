import { FastifyRequest, FastifyReply } from 'fastify';
import { timingSafeEqual } from 'crypto';
import { config } from '../../config';
import { JwtTokenFormat } from '../../modules/oauth/services/jwtTokenFormat';
import { KeyRing } from '../../modules/keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../modules/keys/services/signingKeyStore';
import { RealmService } from '../../modules/realm/services/realm.service';
import { DecisionService } from '../../modules/authorization/services/decision.service';

/**
 * Administering the authority, authorised by the caller's own ROLE.
 *
 * Two ways in, and they are not the same thing. An operator token is a shared break-glass credential
 * that belongs to whoever holds the environment; a principal token belongs to a person, and what it
 * may do is decided by the roles that person holds. The console offers the second so that
 * administering identity is an accountable act with a name against it.
 *
 * The permissions are resolved from the DATABASE rather than read from the token's claims, and that is
 * deliberate. The authority is never an audience for a business token, so an access token issued for
 * an application carries that application's permissions and not these. Resolving live also means a
 * role withdrawn a moment ago is withdrawn here, without waiting for a token to expire.
 */

/** The authority's own resource server, where these permissions are registered. */
const AUTHORITY_RESOURCE_SERVER = 'authority';

export interface AuthorityCaller {
  /** Absent for the operator credential, which is nobody in particular. */
  subjectId?: string;
  realmId?: string;
  roles: string[];
  permissions: Array<{ resource: string; action: string }>;
  viaOperatorToken: boolean;
  /** The operator credential answers true to everything, which is what makes it break-glass. */
  can(resource: string, action: string): boolean;
}

declare module 'fastify' {
  interface FastifyRequest {
    authorityCaller?: AuthorityCaller;
  }
}

function presentedToken(request: FastifyRequest): string {
  const header = request.headers.authorization ?? '';
  return header.startsWith('Bearer ') ? header.slice(7) : '';
}

function matchesOperatorToken(presented: string): boolean {
  const expected = config.app.adminToken;
  if (!expected || !presented) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

function refuse(reply: FastifyReply, status: number, detail: string) {
  return reply.status(status).send({
    type: 'about:blank',
    title: status === 401 ? 'Unauthorized' : 'Forbidden',
    status,
    detail,
  });
}

function operatorCaller(): AuthorityCaller {
  return {
    roles: [],
    permissions: [],
    viaOperatorToken: true,
    can: () => true,
  };
}

function principalCaller(
  subjectId: string,
  realmId: string,
  roles: string[],
  permissions: Array<{ resource: string; action: string }>,
): AuthorityCaller {
  return {
    subjectId,
    realmId,
    roles,
    permissions,
    viaOperatorToken: false,
    can: (resource, action) => permissions.some(
      (permission) => permission.resource === resource && permission.action === action,
    ),
  };
}

/**
 * Authenticates the caller and attaches everything they may do, refusing only when nobody is there.
 *
 * Used by the routes whose required permission depends on what was asked for, which cannot be known
 * before the parameters are read.
 */
export async function requireAuthorityCaller(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const resolved = await resolveCaller(request);
  if (!resolved.caller) return refuse(reply, 401, resolved.detail);
  request.authorityCaller = resolved.caller;
}

/**
 * Requires `resource:action` over the authority's own objects.
 *
 * A caller presenting the operator credential passes without a role check: it is the credential that
 * exists for when the role system itself cannot be relied on, and gating it by a role would make
 * recovery impossible in exactly the situation it is for.
 */
export function requireAuthority(resource: string, action: 'view' | 'manage') {
  return async function handler(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const resolved = await resolveCaller(request);
    if (!resolved.caller) return refuse(reply, 401, resolved.detail);
    if (!resolved.caller.can(resource, action)) {
      return refuse(reply, 403, `Your role does not permit ${action} on ${resource}.`);
    }
    request.authorityCaller = resolved.caller;
  };
}

async function resolveCaller(
  request: FastifyRequest,
): Promise<{ caller: AuthorityCaller | null; detail: string }> {
  {
    const token = presentedToken(request);

    if (matchesOperatorToken(token)) {
      return { caller: operatorCaller(), detail: '' };
    }

    if (!token) {
      return { caller: null, detail: 'An access token or the administrative credential is required.' };
    }

    const db = request.server.db;
    const realms = new RealmService(db);

    // The realm comes from the token's own issuer: this surface is not realm scoped in its path, and
    // taking the realm from a query parameter would let a caller name the realm that authorises them.
    const format = new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(db)), '');
    const unverified = await format.inspect(token);
    const issuer = typeof unverified?.iss === 'string' ? unverified.iss : '';
    const realm = issuer ? await realms.byIssuer(issuer) : null;
    if (!realm || !realm.enabled) {
      return { caller: null, detail: 'The token does not name a realm this authority serves.' };
    }

    // The audience is taken from the token itself: this authority is not a resource server for one
    // audience, so there is no single expected value to compare against here.
    const audience = Array.isArray(unverified?.aud) ? unverified?.aud[0] : unverified?.aud;
    if (typeof audience !== 'string') {
      return { caller: null, detail: 'The access token names no audience.' };
    }
    const verified = await new JwtTokenFormat(new KeyRing(new MongoSigningKeyStore(db)), realm.realmId)
      .verify(token, { issuer: realm.issuer, audience });
    if (!verified || typeof verified.sub !== 'string') {
      return { caller: null, detail: 'The access token is not valid.' };
    }

    const decision = await new DecisionService(db)
      .effectivePermissions(realm.realmId, verified.sub, AUTHORITY_RESOURCE_SERVER);

    return {
      caller: principalCaller(verified.sub, realm.realmId, decision.roles, decision.permissions),
      detail: '',
    };
  }
}
