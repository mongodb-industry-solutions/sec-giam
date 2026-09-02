import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { TOKEN_COLLECTION, RESOURCE_SERVER_COLLECTION, REALM_COLLECTION } from '../../../shared/models/collections';
import { DecisionService } from '../../authorization/services/decision.service';
import { TokenRecord, ActorClaim } from '../models/token.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { OAuthClient } from '../models/client.model';
import { JwtTokenFormat } from './jwtTokenFormat';
import { KeyRing } from '../../keys/services/keyRing.service';
import { newMeta } from '../../../shared/models/base.model';
import { SOFT_ADMISSION_SCOPE } from './clientAuth.service';

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
  permissions?: Array<{ resource: string; action: string }>;
  /** Roles the authority resolved, for the checks a resource server still expresses in roles. */
  roles?: string[];
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

  private get tokens() {
    return this.db.collection<TokenRecord>(TOKEN_COLLECTION);
  }

  /**
   * The resource servers a token from this realm is addressed to.
   *
   * Taken from what is registered rather than configured per client, because a resource server is
   * the thing that knows its own name and registers it. A client may narrow this by declaring its
   * own audience; most never need to.
   *
   * The authority's own surface is excluded deliberately. A token for a business API must not also
   * open the administrative one just because both live in the same realm.
   */
  private async audienceFor(realm: RealmRecord, client: OAuthClient): Promise<string[]> {
    const declared = (client as OAuthClient & { audience?: string[] }).audience;
    if (declared?.length) return declared;

    const servers = await this.db
      .collection<{ name: string; audience: string }>(RESOURCE_SERVER_COLLECTION)
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

  private async record(
    realm: RealmRecord,
    client: OAuthClient,
    input: { jti: string; type: TokenRecord['type']; subjectId?: string; scope: string; expiresAt: Date; sessionId?: string; actor?: ActorClaim },
  ): Promise<void> {
    await this.tokens.insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      tokenId: `tok-${input.jti}`,
      jti: input.jti,
      type: input.type,
      ...(input.subjectId ? { subjectId: input.subjectId } : {}),
      clientId: client.clientId,
      scope: input.scope,
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      issuedAt: new Date().toISOString(),
      expiresAt: input.expiresAt.toISOString(),
      ...(input.actor ? { actor: input.actor } : {}),
      meta: newMeta('Token'),
    } as TokenRecord);
  }

  async issue(request: IssueTokensInput): Promise<TokenResponse> {
    // A soft-admitted client is stripped of authority before anything is minted, so no grant below
    // can hand back more than the reduction allows.
    const input: IssueTokensInput = this.options.reducedAuthority
      ? {
        ...request,
        scope: [SOFT_ADMISSION_SCOPE],
        permissions: undefined,
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
      ...(input.permissions?.length ? { permissions: input.permissions } : {}),
      ...(input.roles?.length ? { roles: input.roles } : {}),
      // Absent, not empty, when there is no cross-realm grant: the token of everybody who administers
      // one realm is byte-for-byte what it was before this existed.
      ...(administrable.length ? { admin_realms: administrable } : {}),
      // Carried so a resource server can bind a person to their own records without asking the
      // authority what the reference names. The authority never resolves it either.
      ...(input.accountHolderRef ? { account_holder: input.accountHolderRef } : {}),
      ...(input.actor ? { act: input.actor } : {}),
    };

    const access_token = await format.issue(accessClaims, kid);
    await this.record(realm, client, {
      jti: accessJti,
      type: 'access',
      subjectId: input.subjectId,
      scope,
      expiresAt: new Date((now + ttl.access) * 1000),
      sessionId: input.sessionId,
      actor: input.actor,
    });

    const response: TokenResponse = {
      access_token,
      token_type: 'Bearer',
      expires_in: ttl.access,
      scope,
    };

    if (input.includeRefreshToken) {
      const refreshJti = uuidv4();
      // Opaque rather than a JWT: nothing verifies a refresh token locally, it is always redeemed
      // here, so giving it a readable payload would disclose claims for no benefit at all.
      response.refresh_token = `${refreshJti}.${uuidv4().replace(/-/g, '')}`;
      await this.record(realm, client, {
        jti: refreshJti,
        type: 'refresh',
        subjectId: input.subjectId,
        scope,
        expiresAt: new Date((now + ttl.refresh) * 1000),
        sessionId: input.sessionId,
      });
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
      await this.record(realm, client, {
        jti: idJti,
        type: 'id',
        subjectId: input.subjectId,
        scope,
        expiresAt: new Date((now + ttl.access) * 1000),
        sessionId: input.sessionId,
      });
    }

    return response;
  }

  /** Looks a refresh token up by the identifier embedded in its opaque form. */
  async findRefreshToken(realmId: string, presented: string): Promise<TokenRecord | null> {
    const jti = presented.split('.')[0];
    if (!jti) return null;
    return this.tokens.findOne({ realmId, jti, type: 'refresh' }, { projection: { _id: 0 } });
  }

  async findByJti(realmId: string, jti: string): Promise<TokenRecord | null> {
    return this.tokens.findOne({ realmId, jti }, { projection: { _id: 0 } });
  }

  async revoke(realmId: string, jti: string, reason: string): Promise<boolean> {
    const result = await this.tokens.updateOne(
      { realmId, jti, revokedAt: { $exists: false } },
      { $set: { revokedAt: new Date().toISOString(), revocationReason: reason } },
    );
    return result.modifiedCount > 0;
  }

  /** Revokes everything issued under a session, which is what a logout has to do. */
  async revokeSession(realmId: string, sessionId: string, reason: string): Promise<number> {
    const result = await this.tokens.updateMany(
      { realmId, sessionId, revokedAt: { $exists: false } },
      { $set: { revokedAt: new Date().toISOString(), revocationReason: reason } },
    );
    return result.modifiedCount;
  }
}
