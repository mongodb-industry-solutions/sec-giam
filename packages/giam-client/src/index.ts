import { createPublicKey, verify as cryptoVerify, KeyObject } from 'crypto';

/**
 * The verifier every resource server uses.
 *
 * One implementation rather than one per application, because four verifiers is four opinions about
 * which forgeries to refuse, and they will not stay the same. The list of defects below is not a
 * matter of taste: each is an accepted forgery rather than a failed parse, so a verifier that merely
 * happens not to handle one today accepts it the day a library changes a default.
 *
 * The defining property of the decentralised model: this holds nothing secret and asks the authority
 * nothing at verification time. It downloads PUBLIC keys, caches them, and checks a signature in
 * process, which is why a compromised resource server cannot mint a token.
 */

export interface GiamClientOptions {
  /** The realm issuer. Everything else is discovered, so a deployment configures one URL. */
  issuerUrl: string;
  /** What a token must name in `aud`. Omitted means any audience the caller accepts. */
  audience?: string;
  /** How long a fetched key set is reused. A stale copy is safe. */
  jwksCacheSeconds?: number;
  /** Injectable so a test can drive discovery and key fetching without a network. */
  fetchImpl?: typeof fetch;
}

export interface VerifiedClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  scope: string[];
  /**
   * Full permission strings, `resource:action`.
   *
   * v40 changed both the shape and the default. It was `[{resource, action}]`; it is now one string
   * per entry, because that is the same spelling a role and a policy use and there is nothing to
   * convert between the three places a permission appears.
   *
   * ABSENT unless the client asked to narrow. A JWT travels in an HTTP header and proxies commonly
   * cut around 8 KB, so a token carrying every expanded permission fails intermittently depending
   * on which proxy the request crossed. Read `roles` and expand, or ask for what you need.
   */
  permissions: string[];
  roles: string[];
  clientId?: string;
  sessionId?: string;
  sessionEpoch?: number;
  act?: Record<string, unknown>;
  [claim: string]: unknown;
}

/** Why a token was refused. Recorded so a rising count of one cause is visible. */
export type FailureCause =
  | 'malformed'
  | 'unexpected_alg'
  | 'header_key_injection'
  | 'missing_kid'
  | 'unknown_kid'
  | 'alg_mismatch'
  | 'bad_signature'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'revoked';

export interface VerifierMetrics {
  cacheHits: number;
  refetches: number;
  /** A rising count is the early warning that the authority is unreachable. */
  staleServes: number;
  failuresByCause: Record<string, number>;
}

interface CachedKeySet {
  keys: Map<string, KeyObject>;
  algByKid: Map<string, string>;
  fetchedAt: number;
}

export class GiamClient {
  private cache: CachedKeySet | null = null;

  private jwksUri: string | null = null;

  private inFlight: Promise<void> | null = null;

  private readonly lastRefetchByKid = new Map<string, number>();

  /**
   * Revoked token identifiers, with the expiry of the token they came from.
   *
   * What makes the hybrid model honest rather than a fudge: local verification then respects a
   * revocation within the delivery latency of the notification, instead of within the token
   * lifetime. Entries are dropped at the token's own expiry, because after that the signature check
   * refuses it anyway and keeping it would grow without bound.
   */
  private readonly denyList = new Map<string, number>();

  readonly metrics: VerifierMetrics = {
    cacheHits: 0,
    refetches: 0,
    staleServes: 0,
    failuresByCause: {},
  };

  constructor(private readonly options: GiamClientOptions) {}

  private get fetchImpl(): typeof fetch {
    return this.options.fetchImpl ?? fetch;
  }

  private fail(cause: FailureCause): null {
    this.metrics.failuresByCause[cause] = (this.metrics.failuresByCause[cause] ?? 0) + 1;
    return null;
  }

  /** The key set URL is discovered, never assumed: the path beneath an issuer is the authority's. */
  private async discoverJwksUri(): Promise<string> {
    if (this.jwksUri) return this.jwksUri;
    const issuer = this.options.issuerUrl.replace(/\/+$/, '');
    const response = await this.fetchImpl(`${issuer}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`discovery answered ${response.status}`);
    const metadata = await response.json() as { jwks_uri?: string };
    if (!metadata.jwks_uri) throw new Error('discovery document carries no jwks_uri');
    this.jwksUri = metadata.jwks_uri;
    return this.jwksUri;
  }

  private async fetchKeySet(): Promise<void> {
    const uri = await this.discoverJwksUri();
    const response = await this.fetchImpl(uri, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`key set answered ${response.status}`);
    const document = await response.json() as { keys?: Array<Record<string, unknown>> };

    const keys = new Map<string, KeyObject>();
    const algByKid = new Map<string, string>();
    for (const jwk of document.keys ?? []) {
      const kid = typeof jwk.kid === 'string' ? jwk.kid : null;
      if (!kid) continue;
      try {
        keys.set(kid, createPublicKey({ key: jwk as never, format: 'jwk' }));
        algByKid.set(kid, typeof jwk.alg === 'string' ? jwk.alg : 'RS256');
      } catch {
        // One unparseable entry must not invalidate a whole key set.
      }
    }
    this.cache = { keys, algByKid, fetchedAt: Date.now() };
    this.metrics.refetches += 1;
  }

  /** Shared across concurrent callers, so a burst produces one request rather than one each. */
  private async ensureKeySet(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    this.inFlight = this.fetchKeySet().finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  private async resolveKey(kid: string): Promise<{ key: KeyObject; alg: string } | null> {
    const ttl = (this.options.jwksCacheSeconds ?? 900) * 1000;
    const fresh = this.cache && Date.now() - this.cache.fetchedAt < ttl;

    if (!fresh) {
      try {
        await this.ensureKeySet();
      } catch {
        // Serve stale rather than fail closed. The alternative is a total outage of this application
        // every time the authority blinks, and it is safe: an old public key can only validate
        // signatures the authority itself produced.
        if (!this.cache) return null;
        this.metrics.staleServes += 1;
      }
    } else {
      this.metrics.cacheHits += 1;
    }

    const existing = this.cache?.keys.get(kid);
    if (existing) return { key: existing, alg: this.cache!.algByKid.get(kid) ?? 'RS256' };

    // Rotation or a new replica, both ordinary. Rate limited per key so a token carrying a forged id
    // cannot be used to hammer the authority.
    const lastAttempt = this.lastRefetchByKid.get(kid) ?? 0;
    if (Date.now() - lastAttempt < 60_000) return null;
    this.lastRefetchByKid.set(kid, Date.now());
    try {
      await this.ensureKeySet();
    } catch {
      return null;
    }
    const found = this.cache?.keys.get(kid);
    return found ? { key: found, alg: this.cache!.algByKid.get(kid) ?? 'RS256' } : null;
  }

  /** Records a revocation received out of band, so local verification respects it immediately. */
  revoke(jti: string, expiresAtEpochSeconds: number): void {
    this.denyList.set(jti, expiresAtEpochSeconds);
    // Opportunistic sweep: entries are worthless once the signature check would refuse the token
    // anyway, and keeping them would grow the list without bound.
    const now = Math.floor(Date.now() / 1000);
    for (const [id, expiry] of this.denyList) {
      if (expiry <= now) this.denyList.delete(id);
    }
  }

  isRevoked(jti: string): boolean {
    return this.denyList.has(jti);
  }

  private decode(segment: string): Record<string, unknown> | null {
    try {
      return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  /**
   * Verifies a token against the authority's published key set.
   *
   * Each refusal below is an accepted forgery if it is missing, which is why every one is explicit
   * rather than left to a library default.
   */
  async verify(token: string, expected?: { audience?: string }): Promise<VerifiedClaims | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return this.fail('malformed');

    const header = this.decode(parts[0]);
    if (!header) return this.fail('malformed');

    // `none` makes an unsigned token valid. A symmetric algorithm lets anyone holding the PUBLIC key
    // sign, and a public key is published to everyone by design.
    if (header.alg !== 'RS256') return this.fail('unexpected_alg');
    // These four let a token nominate the key that validates it, which is a token asserting its own
    // authenticity. Their presence is grounds for refusal, not merely something to ignore.
    if (header.jku || header.jwk || header.x5u || header.x5c) return this.fail('header_key_injection');
    if (typeof header.kid !== 'string') return this.fail('missing_kid');

    const resolved = await this.resolveKey(header.kid);
    if (!resolved) return this.fail('unknown_kid');
    // The algorithm the AUTHORITY published for this key, not the one the token asked for.
    if (resolved.alg !== 'RS256') return this.fail('alg_mismatch');

    const signatureValid = cryptoVerify(
      'sha256',
      Buffer.from(`${parts[0]}.${parts[1]}`),
      resolved.key,
      Buffer.from(parts[2], 'base64url'),
    );
    if (!signatureValid) return this.fail('bad_signature');

    const claims = this.decode(parts[1]);
    if (!claims) return this.fail('malformed');

    if (claims.iss !== this.options.issuerUrl) return this.fail('wrong_issuer');

    const wantedAudience = expected?.audience ?? this.options.audience;
    if (wantedAudience) {
      const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
      if (!audience.includes(wantedAudience)) return this.fail('wrong_audience');
    }

    const now = Math.floor(Date.now() / 1000);
    const skew = 60;
    if (typeof claims.exp === 'number' && claims.exp + skew < now) return this.fail('expired');
    if (typeof claims.nbf === 'number' && claims.nbf - skew > now) return this.fail('not_yet_valid');

    if (typeof claims.jti === 'string' && this.isRevoked(claims.jti)) return this.fail('revoked');

    return {
      ...claims,
      sub: String(claims.sub ?? ''),
      iss: String(claims.iss),
      aud: claims.aud as string | string[],
      exp: Number(claims.exp ?? 0),
      scope: typeof claims.scope === 'string' ? claims.scope.split(' ').filter(Boolean) : [],
      permissions: Array.isArray(claims.permissions)
        ? (claims.permissions as unknown[])
          /**
           * Strings only, and a v39-shaped entry is CONVERTED rather than dropped.
           *
           * Not a compatibility shim for the old authority: a verifier may hold a token minted
           * minutes before an authority upgrade, and refusing it would turn a rolling deploy into
           * an outage. The conversion is one expression and it disappears when the last such token
           * has expired, which is five minutes.
           */
          .map((entry) => (typeof entry === 'string'
            ? entry
            : `${(entry as { resource?: string }).resource ?? ''}:${(entry as { action?: string }).action ?? ''}`))
          .filter((entry) => entry.length > 1 && !entry.startsWith(':') && !entry.endsWith(':'))
        : [],
      roles: Array.isArray(claims.roles) ? claims.roles as string[] : [],
      clientId: typeof claims.client_id === 'string' ? claims.client_id : undefined,
      sessionId: typeof claims.sid === 'string' ? claims.sid : undefined,
      sessionEpoch: typeof claims.session_epoch === 'number' ? claims.session_epoch : undefined,
      act: claims.act as Record<string, unknown> | undefined,
    };
  }

  /**
   * Asks the authority whether a token is active.
   *
   * The centralised model: authoritative about revocation and current status, at the cost of a round
   * trip and a hard dependency on the hot path of whatever calls it. For the operations where being
   * wrong is expensive to undo.
   */
  async introspect(
    token: string,
    credentials: { clientId: string; clientSecret: string },
  ): Promise<{ active: boolean; [claim: string]: unknown }> {
    const issuer = this.options.issuerUrl.replace(/\/+$/, '');
    try {
      const response = await this.fetchImpl(`${issuer}/protocol/openid-connect/token/introspect`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          token,
          client_id: credentials.clientId,
          client_secret: credentials.clientSecret,
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) return { active: false };
      return await response.json() as { active: boolean };
    } catch {
      // Fail CLOSED here, unlike local verification. Introspection is used precisely where being
      // wrong is expensive, so an unanswerable question must not be treated as a yes.
      return { active: false };
    }
  }

  /** Forgets what was cached, so the next verification rediscovers. */
  reset(): void {
    this.cache = null;
    this.jwksUri = null;
    this.lastRefetchByKid.clear();
    this.denyList.clear();
  }
}

/** Reads a logout or revocation notification the authority signed. */
export function isLogoutToken(claims: Record<string, unknown>): boolean {
  const events = claims.events as Record<string, unknown> | undefined;
  return Boolean(events && 'http://schemas.openid.net/event/backchannel-logout' in events);
}

/**
 * The published role catalog, as a verifier caches it.
 *
 * `catalogVersion` bumps whenever any resource catalog changes, so a cache holds until the number
 * moves. Without a version a verifier either re-fetches per request, which defeats the point, or
 * caches forever, which is how a withdrawn permission keeps working.
 */
export interface RoleCatalog {
  catalogVersion: number;
  roles: Array<{ name: string; permissions: string[] }>;
}

/**
 * What a caller may actually do, from the claims plus the catalog.
 *
 * The union of the permissions carried explicitly and those the carried roles expand to. Union
 * rather than either-or, because a token may legitimately carry both: a client that narrowed still
 * gets its roles, so a resource server enforcing roles keeps working.
 *
 * Expansion is the verifier's job by design. It is what lets a token carry three roles instead of
 * three hundred permissions, which is the difference between a token that always fits in a header
 * and one that fails on whichever proxy is strictest.
 */
export function effectivePermissions(
  claims: Pick<VerifiedClaims, 'permissions' | 'roles'>,
  catalog: RoleCatalog | null,
): Set<string> {
  const held = new Set<string>(claims.permissions);
  if (!catalog) return held;
  const byName = new Map(catalog.roles.map((role) => [role.name, role.permissions]));
  for (const role of claims.roles) {
    for (const permission of byName.get(role) ?? []) held.add(permission);
  }
  return held;
}

/**
 * Whether a caller holds one permission.
 *
 * ABSENCE IS REFUSAL. A token carrying neither claim, or a catalog that has not loaded, grants
 * nothing: an unresolved authority must never read as an unrestricted one, and that is the single
 * most important line in this file.
 */
export function holdsPermission(
  claims: Pick<VerifiedClaims, 'permissions' | 'roles'>,
  catalog: RoleCatalog | null,
  resource: string,
  action: string,
): boolean {
  return effectivePermissions(claims, catalog).has(`${resource}:${action}`);
}

/**
 * Fetches the published role catalog, cached against its own version.
 *
 * The catalog is what turns the `roles` a token carries into the permissions a resource server
 * enforces. Cached because re-fetching per request would defeat the reason roles are carried at
 * all, and re-validated by `catalogVersion` because a cache with no invalidation is how a
 * withdrawn permission keeps working.
 *
 * A fetch failure returns the LAST GOOD catalog rather than null, for the same reason the key set
 * does: an authority outage must not turn into a platform outage. It returns null only when there
 * has never been one, and null denies everything, which is the correct direction to fail.
 */
export function createCatalogCache(options: {
  origin: string;
  realm: string;
  /** How long before the version is re-checked. Short: the check is one small request. */
  ttlMs?: number;
  token?: () => Promise<string | undefined>;
}) {
  let cached: RoleCatalog | null = null;
  let fetchedAt = 0;
  const ttl = options.ttlMs ?? 60_000;

  return {
    /** The catalog, refreshed when stale. Never throws. */
    async get(): Promise<RoleCatalog | null> {
      if (cached && Date.now() - fetchedAt < ttl) return cached;
      try {
        const bearer = await options.token?.();
        const response = await fetch(
          `${options.origin.replace(/\/$/, '')}/realms/${options.realm}/permissions`,
          {
            headers: bearer ? { authorization: `Bearer ${bearer}` } : {},
            signal: AbortSignal.timeout(5_000),
          },
        );
        if (!response.ok) return cached;
        const body = await response.json() as RoleCatalog;
        if (!Array.isArray(body?.roles)) return cached;
        cached = { catalogVersion: Number(body.catalogVersion ?? 0), roles: body.roles };
        fetchedAt = Date.now();
        return cached;
      } catch {
        // The last good catalog, or null when there has never been one. Null denies everything.
        return cached;
      }
    },
    /** For a test, or for an operator forcing a refresh after a deploy. */
    invalidate(): void { fetchedAt = 0; },
  };
}
