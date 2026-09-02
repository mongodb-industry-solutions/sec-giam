import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { RESOURCE_COLLECTION, REALM_COLLECTION, SESSION_COLLECTION } from '../../../shared/models/collections';
import { DecisionService } from '../../authorization/services/decision.service';
import { ActorClaim } from '../models/actor.model';
import { SessionRecord, RefreshClaims, isLive } from '../../authentication/models/session.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { OAuthClient } from '../models/client.model';
import { JwtTokenFormat } from './jwtTokenFormat';
import { KeyRing } from '../../keys/services/keyRing.service';
import { newMeta } from '../../../shared/models/base.model';
import { SOFT_ADMISSION_SCOPE } from './clientAuth.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { attenuate } from './attenuate';

/** The name the authority registers its OWN permissions under. Never an audience for a business token. */
const AUTHORITY_RESOURCE_SERVER = 'authority';

export interface IssueTokensInput {
  realm: RealmRecord;
  client: OAuthClient;
  subjectId?: string;
  scope: string[];
  sessionId?: string;
  sessionEpoch?: number;
  /** Permissions the resource server enforces, resolved by the decision point at issuance. */
  /**
   * Full permission strings, `resource:action`.
   *
   * One string per entry rather than an object with two keys: this claim travels in every token,
   * and the object form spent two quoted keys of JSON on what a single string says.
   */
  permissions?: string[];
  /** Roles the authority resolved, for the checks a resource server still expresses in roles. */
  roles?: string[];
  /**
   * Permissions the CLIENT asked for, to obtain a narrower token than its roles would give.
   *
   * Intersected with what the roles grant, never unioned. Absent means the default, which is roles
   * only.
   */
  requestedPermissions?: string[];
  /** Opaque binding to the business record a self-scoped principal owns. */
  accountHolderRef?: string;
  /** Delegation chain, when the token was obtained by exchange rather than issued directly. */
  actor?: ActorClaim;
  nonce?: string;
  includeRefreshToken?: boolean;
  includeIdToken?: boolean;
  /** Profile claims for the id token, so this service needs no directory read of its own. */
  idTokenClaims?: Record<string, unknown>;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
  refresh_token?: string;
  id_token?: string;
}

/**
 * Mints the tokens and records what was issued.
 *
 * The record is not what a resource server checks: verification is a signature check against the
 * published key set, with no call here. What the record buys is the ability to revoke, to detect a
 * replay, and to say afterwards what was issued to whom, which a stateless design cannot do.
 */
export class TokenIssuer {
  /**
   * `reducedAuthority` is what a soft admission gets: the scope is cut to the minimum, no permissions
   * or roles claim is written, and no refresh token is minted. Applied HERE rather than at each call
   * site, because a reduction that depends on every grant remembering is a reduction with holes.
   */
  constructor(
    private readonly db: Db,
    private readonly ring: KeyRing,
    private readonly options: { reducedAuthority?: boolean } = {},
  ) {}

  private get sessions() {
    return this.db.collection<SessionRecord>(SESSION_COLLECTION);
  }

  private async audienceFor(realm: RealmRecord, client: OAuthClient): Promise<string[]> {
    const declared = (client as OAuthClient & { audience?: string[] }).audience;
    if (declared?.length) return declared;

    const servers = await this.db
      .collection<{ name: string; audience: string }>(RESOURCE_COLLECTION)
      .find({ realmId: realm.realmId }, { projection: { _id: 0, name: 1, audience: 1 } })
      .toArray();

    const addressed = servers
      .filter((server) => server.name !== AUTHORITY_RESOURCE_SERVER)
      .map((server) => server.audience)
      .filter(Boolean);

    // A realm with no registered resource server yet: the client's own id keeps the claim populated
    // rather than emitting a token with an empty audience, which a verifier must refuse.
    return addressed.length > 0 ? addressed : [client.clientId];
  }

  /**
   * The realms this subject may administer BESIDES the one issuing the token.
   *
   * Written as explicit data, `[{ id, name }]`, and never as a flag a client would have to interpret.
   * Both halves are there on purpose: the id is what an authorization decision is made against, and
   * the name is what appears in a request path, so a console reading this claim never has to look one
   * up from the other and never has to guess which it was given.
   *
   * The claim widens nothing by itself. The token is still issued by, signed by and addressed from
   * ONE realm; every request against a named realm is re-decided against the stored grant. What the
   * claim buys is that a client can offer the switch without discovering it by trial and error.
   */
  private async administrableRealmClaim(
    realm: RealmRecord,
    subjectId: string,
  ): Promise<Array<{ id: string; name: string }>> {
    const granted = await new DecisionService(this.db).grantedRealmIds(realm.realmId, subjectId);
    if (granted.length === 0) return [];
    const realms = await this.db
      .collection<{ realmId: string; name: string; enabled?: boolean }>(REALM_COLLECTION)
      .find({ realmId: { $in: granted }, enabled: true }, { projection: { _id: 0, realmId: 1, name: 1 } })
      .toArray();
    return realms.map((entry) => ({ id: entry.realmId, name: entry.name }));
  }

  private ttl(realm: RealmRecord, client: OAuthClient): { access: number; refresh: number } {
    return {
      access: client.tokenPolicy?.accessTokenTtlSeconds ?? realm.tokenPolicy.accessTokenTtlSeconds,
      refresh: client.tokenPolicy?.refreshTokenTtlSeconds ?? realm.tokenPolicy.refreshTokenTtlSeconds,
    };
  }

  async issue(request: IssueTokensInput): Promise<TokenResponse> {
    // A soft-admitted client is stripped of authority before anything is minted, so no grant below
    // can hand back more than the reduction allows.
    const input: IssueTokensInput = this.options.reducedAuthority
      ? {
        ...request,
        scope: [SOFT_ADMISSION_SCOPE],
        permissions: undefined,
        requestedPermissions: undefined,
        roles: undefined,
        accountHolderRef: undefined,
        includeRefreshToken: false,
      }
      : request;

    const { realm, client } = input;
    const ttl = this.ttl(realm, client);
    const now = Math.floor(Date.now() / 1000);
    const scope = input.scope.join(' ');

    const format = new JwtTokenFormat(this.ring, realm.realmId);
    const kid = await this.ring.signingKid(realm.realmId);

    // Suppressed for a soft admission along with everything else it is stripped of: a reduced token
    // must not advertise authority it is not carrying.
    const administrable = this.options.reducedAuthority || !input.subjectId
      ? []
      : await this.administrableRealmClaim(realm, input.subjectId);

    /**
     * What the token will actually carry, after attenuation.
     *
     * Computed here rather than inside the claim literal, because a dropped permission has to be
     * RECORDED and a claim literal is no place to emit an audit event from.
     */
    const narrowed = attenuate({
      held: input.permissions ?? [],
      requested: input.requestedPermissions,
      roles: input.roles ?? [],
    });

    if (narrowed.dropped.length > 0) {
      /**
       * A client asked for something its subject does not hold.
       *
       * Recorded rather than refused. Refusing would make a client that asks for a superset fail
       * entirely, which pushes clients towards asking for nothing and taking the widest token
       * available. Dropping and recording keeps the narrow request worth making, and leaves
       * evidence when an application's idea of its own authority has drifted from the truth.
       */
      void new SecurityEventService(this.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'token',
        action: 'token.permissions_narrowed',
        outcome: 'success',
        clientId: client.clientId,
        ...(input.subjectId ? { subjectId: input.subjectId } : {}),
        detail: {
          dropped: narrowed.dropped,
          granted: narrowed.permissions,
          reason: 'a token may only narrow what the roles grant, never widen it',
        },
      });
    }

    const accessJti = uuidv4();
    const accessClaims: Record<string, unknown> = {
      iss: realm.issuer,
      /**
       * The audience names the RESOURCE SERVERS this token is for, per RFC 9068, not the client that
       * asked for it.
       *
       * It named the client until v39 P12, and that was wrong in a way nothing detected: a resource
       * server checking the audience against its own registered name could never match, so either it
       * did not check at all, or it checked something that always failed. Both consumers turned out
       * to be in the first state. Naming the resource server makes the claim mean what a verifier
       * assumes it means, which is what stops a token minted for one API opening another.
       */
      aud: await this.audienceFor(realm, client),
      sub: input.subjectId ?? client.clientId,
      jti: accessJti,
      iat: now,
      nbf: now,
      exp: now + ttl.access,
      scope,
      client_id: client.clientId,
      ...(input.sessionId ? { sid: input.sessionId } : {}),
      // The epoch travels in the token so a resource server can refuse a whole generation at once,
      // without listing outstanding tokens.
      ...(input.sessionEpoch !== undefined ? { session_epoch: input.sessionEpoch } : {}),
      /**
       * P9. ROLES BY DEFAULT, permissions only to narrow.
       *
       * A JWT travels in an HTTP header and proxies commonly cut around 8 KB. A token carrying three
       * hundred expanded permissions is a token that fails intermittently in production and is very
       * hard to diagnose, because the failure depends on which proxy the request happened to cross.
       * Three roles, expanded at the decision point, is the only form that scales.
       *
       * A client may ask for specific permissions instead, to shrink its own blast radius, and the
       * INVARIANT is that asking can only narrow: `narrowed` intersects the request with what the
       * roles actually grant, so a permission the subject does not hold is dropped rather than
       * granted. That is what makes it safe for a client to ask at all.
       */
      ...(narrowed.permissions.length ? { permissions: narrowed.permissions } : {}),
      ...(narrowed.roles.length ? { roles: narrowed.roles } : {}),
      // Absent, not empty, when there is no cross-realm grant: the token of everybody who administers
      // one realm is byte-for-byte what it was before this existed.
      ...(administrable.length ? { admin_realms: administrable } : {}),
      // Carried so a resource server can bind a person to their own records without asking the
      // authority what the reference names. The authority never resolves it either.
      ...(input.accountHolderRef ? { account_holder: input.accountHolderRef } : {}),
      ...(input.actor ? { act: input.actor } : {}),
    };

    const access_token = await format.issue(accessClaims, kid);

    const response: TokenResponse = {
      access_token,
      token_type: 'Bearer',
      expires_in: ttl.access,
      scope,
    };

    /**
     * The refresh token, as a JWT over the session's current generation. NOTHING IS STORED.
     *
     * It carries `sid` and `gen`, which is everything redemption needs: the session says whether
     * access is still live, and the generation is what makes a replay detectable. Signed, so it
     * cannot be forged, and a readable payload discloses nothing its holder does not already know.
     *
     * A session is REQUIRED. Without one there is nothing to rotate against, and a refresh token
     * that rotates against nothing is a long-lived bearer credential with extra steps. That is also
     * what makes `client_credentials` refresh-free without a special case: it creates no session.
     */
    if (input.includeRefreshToken && input.sessionId) {
      const session = await this.sessions.findOne(
        { realmId: realm.realmId, sessionId: input.sessionId },
        { projection: { _id: 0, refreshGen: 1 } },
      );
      const refreshFormat = new JwtTokenFormat(this.ring, realm.realmId, 'JWT');
      response.refresh_token = await refreshFormat.issue({
        iss: realm.issuer,
        // Addressed to the issuer itself: this token is redeemed here and accepted nowhere else.
        aud: realm.issuer,
        sub: input.subjectId ?? client.clientId,
        sid: input.sessionId,
        gen: session?.refreshGen ?? 0,
        client_id: client.clientId,
        jti: uuidv4(),
        iat: now,
        exp: now + ttl.refresh,
      }, kid);
    }

    if (input.includeIdToken && input.subjectId) {
      const idJti = uuidv4();
      const idFormat = new JwtTokenFormat(this.ring, realm.realmId, 'JWT');
      response.id_token = await idFormat.issue({
        iss: realm.issuer,
        aud: client.clientId,
        sub: input.subjectId,
        jti: idJti,
        iat: now,
        exp: now + ttl.access,
        ...(input.nonce ? { nonce: input.nonce } : {}),
        ...(input.idTokenClaims ?? {}),
      }, kid);
    }

    return response;
  }

  /**
   * Redeems a refresh token: verifies it, checks the generation, and rotates.
   *
   * The generation check IS the reuse detection RFC 9700 asks for, and it needs one integer rather
   * than a stored copy of every token. Three outcomes, and the third is the one that matters:
   *
   * - the generation matches, so this is the current token: incremented, and the caller may mint.
   * - no session, so access is not live: refused, and there is nothing to clean up.
   * - the generation is LOWER, so a token that was already rotated has been presented again. The
   *   legitimate holder cannot do that, so the assumption is theft and the WHOLE SESSION is
   *   deleted. Refusing just this one would leave the thief's next attempt equally cheap.
   */
  async redeemRefresh(
    realmId: string,
    presented: string,
  ): Promise<
    | { ok: true; sessionId: string; subjectId?: string; clientId: string; generation: number }
    | { ok: false; cause: 'invalid' | 'expired' | 'no_session' | 'reuse_detected'; sessionId?: string; subjectId?: string }
  > {
    const format = new JwtTokenFormat(this.ring, realmId, 'JWT');
    const realm = await this.db
      .collection<{ realmId: string; issuer: string }>(REALM_COLLECTION)
      .findOne({ realmId }, { projection: { _id: 0, issuer: 1 } });
    if (!realm) return { ok: false, cause: 'invalid' };

    // Verified, not merely decoded. A refresh token is redeemed here and nowhere else, so this is
    // the only place its signature is ever checked, which makes skipping it unrecoverable.
    const verified = await format.verify(presented, { issuer: realm.issuer, audience: realm.issuer });
    if (!verified) return { ok: false, cause: 'invalid' };
    const claims = verified as unknown as RefreshClaims & { exp?: number };
    if (!claims.sid || typeof claims.gen !== 'number') return { ok: false, cause: 'invalid' };
    if (claims.exp && claims.exp * 1000 <= Date.now()) {
      return { ok: false, cause: 'expired', sessionId: claims.sid, subjectId: claims.sub };
    }

    /**
     * Guarded on the generation, so the check and the increment are ONE atomic operation.
     *
     * Reading then writing would leave a window in which two concurrent refreshes both see the
     * current generation and both succeed, which is precisely the replay this exists to detect.
     */
    const rotated = await this.sessions.findOneAndUpdate(
      { realmId, sessionId: claims.sid, refreshGen: claims.gen },
      { $inc: { refreshGen: 1 }, $set: { lastSeenAt: new Date().toISOString() } },
      { returnDocument: 'after', projection: { _id: 0, refreshGen: 1, subjectId: 1, clientId: 1 } },
    );
    if (rotated) {
      return {
        ok: true,
        sessionId: claims.sid,
        subjectId: rotated.subjectId,
        clientId: claims.client_id,
        generation: rotated.refreshGen,
      };
    }

    // The guard failed. Either the session is gone, which is a refusal and nothing more, or it is
    // there at a different generation, which is a replay.
    const session = await this.sessions.findOne(
      { realmId, sessionId: claims.sid },
      { projection: { _id: 0, refreshGen: 1, subjectId: 1 } },
    );
    if (!session) {
      return { ok: false, cause: 'no_session', sessionId: claims.sid, subjectId: claims.sub };
    }

    await this.sessions.deleteOne({ realmId, sessionId: claims.sid });
    return {
      ok: false,
      cause: 'reuse_detected',
      sessionId: claims.sid,
      subjectId: session.subjectId ?? claims.sub,
    };
  }

  /**
   * Revocation, all four shapes, and every one of them is a delete.
   *
   * The absence of the session document is the revocation signal, so there is no status to set and
   * no entry to keep alive until the last affected token expires.
   */
  /** Whether access under this session is still live. The one read introspection needs. */
  async sessionIsLive(realmId: string, sessionId: string): Promise<boolean> {
    const session = await this.sessions.findOne(
      { realmId, sessionId },
      { projection: { _id: 0, expiresAt: 1, idleExpiresAt: 1 } },
    );
    // Absence is revocation. The expiry checks cover the window before the TTL sweep notices.
    return Boolean(session) && isLive(session as SessionRecord);
  }

  async revokeSession(realmId: string, sessionId: string): Promise<number> {
    const outcome = await this.sessions.deleteOne({ realmId, sessionId });
    return outcome.deletedCount;
  }

  async revokeSubject(realmId: string, subjectId: string): Promise<number> {
    const outcome = await this.sessions.deleteMany({ realmId, subjectId });
    return outcome.deletedCount;
  }

  async revokeClient(realmId: string, clientId: string): Promise<number> {
    const outcome = await this.sessions.deleteMany({ realmId, clientId });
    return outcome.deletedCount;
  }

  async revokeRealm(realmId: string): Promise<number> {
    const outcome = await this.sessions.deleteMany({ realmId });
    return outcome.deletedCount;
  }
}
