import { FastifyRequest, FastifyReply } from 'fastify';
import { isAdminAuthorized } from './adminAuth';
import { JwtTokenFormat } from '../../modules/oauth/services/jwtTokenFormat';
import { KeyRing } from '../../modules/keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../modules/keys/services/signingKeyStore';
import { RealmService } from '../../modules/realm/services/realm.service';
import { DecisionService } from '../../modules/authorization/services/decision.service';
import { SecurityEventService } from '../../modules/audit/services/securityEvent.service';
import { permissionString } from '../../modules/authorization/models/resource.model';

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
  /** The realm being acted on: the one in the path where there is one, otherwise the token's own. */
  realmId?: string;
  /** The realm that signed the token. Differs from `realmId` only under a cross-realm grant. */
  homeRealmId?: string;
  roles: string[];
  /** Full permission strings, `resource:action`. */
  permissions: string[];
  viaOperatorToken: boolean;
  /** The widest scope any role held grants: `self` sees only its own records, `all` sees the realm. */
  scopeKind: 'self' | 'all';
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
    scopeKind: 'all',
    can: () => true,
  };
}

function principalCaller(
  subjectId: string,
  realmId: string,
  homeRealmId: string,
  roles: string[],
  permissions: string[],
  scopeKind: 'self' | 'all',
): AuthorityCaller {
  return {
    subjectId,
    realmId,
    homeRealmId,
    roles,
    permissions,
    viaOperatorToken: false,
    scopeKind,
    can: (resource, action) => permissions.includes(permissionString(resource, action)),
  };
}

/**
 * Authenticates the caller and attaches everything they may do, refusing only when nobody is there.
 *
 * Used by the routes whose required permission depends on what was asked for, which cannot be known
 * before the parameters are read.
 */
export async function requireAuthorityCaller(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  // A bearer token is expected here too, so a refusal carries the RFC 6750 challenge.
  request.bearerProtected = true;
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
export function requireAuthority(resource: string, action: string) {
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

    // Break-glass is checked FIRST, and it is the same credential the operational surface accepts:
    // the deploy-time token, or the session the operator sign-in mints. It has to work when the role
    // system cannot be relied on, which is precisely what an identity outage looks like.
    if (isAdminAuthorized(request.headers.authorization)) {
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

    /**
     * The realm being ACTED ON, where the path names one.
     *
     * Taking it from the path rather than from a query parameter is the same rule as before: a caller
     * may not name the realm that authorises them, and here they do not. The token is still verified
     * against its own issuer's keys above; naming a different realm below only ever narrows what is
     * granted, because reaching one takes a stored assignment scoped to it.
     */
    const named = (request.params as { realm?: string } | undefined)?.realm;
    const target = named ? await realms.byName(named) : null;
    if (named && (!target || !target.enabled)) {
      return { caller: null, detail: 'The path names no realm this authority serves.' };
    }
    const targetRealmId = target?.realmId ?? realm.realmId;

    const decision = await new DecisionService(db).effectivePermissionsIn(
      realm.realmId, verified.sub, AUTHORITY_RESOURCE_SERVER, targetRealmId,
    );

    if (targetRealmId !== realm.realmId) {
      await new SecurityEventService(db).record({
        realmId: targetRealmId,
        tenantId: target!.tenantId,
        category: 'authorization',
        action: 'authorization.cross_realm_access',
        outcome: decision.permissions.length > 0 ? 'success' : 'failure',
        decision: decision.permissions.length > 0 ? 'allow' : 'deny',
        subjectId: verified.sub,
        // Both realms, because the question about a crossing is which two realms it joined.
        detail: { homeRealm: realm.name, homeRealmId: realm.realmId, targetRealm: target!.name, targetRealmId },
        target: { type: 'realm', ref: targetRealmId },
      });
    }

    return {
      caller: principalCaller(
        verified.sub, targetRealmId, realm.realmId, decision.roles, decision.permissions, decision.scopeKind,
      ),
      detail: '',
    };
  }
}
