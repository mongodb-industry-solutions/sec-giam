import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A realm: a trust and key boundary.
 *
 * Its own issuer, its own signing keys, its own JWKS. A token minted in one realm is refused by
 * another, and that refusal is what makes an institutional boundary real rather than declared. A
 * tenant is a data boundary INSIDE a realm; the two are separate on purpose, because conflating them
 * is what makes multi-tenancy unretrofittable.
 *
 * The name is a slug and no longer a closed set of values: adding a realm is data, not a code change.
 */
export interface RealmRecord extends Scoped {
  realmId: string;
  name: string;
  displayName: string;
  /** Absolute issuer URL. It ends up in every token as `iss`, so it must be reachable by a verifier. */
  issuer: string;
  enabled: boolean;
  /**
   * Alternative names a caller may use on the wire.
   *
   * Data rather than a constant, which is the point: the platform's `local` alias used to be a
   * hardcoded special case in a resolver, and here it is a value on the record it belongs to.
   */
  aliases: string[];
  /** Shown on the sign-in screen. Kept because the platform's domain notice is demo copy that matters. */
  notice?: string;
  registration: {
    selfServiceEnabled: boolean;
    autoApprove: boolean;
  };
  /** Lifetimes, out of a service's hardcoding and onto the record an operator can edit. */
  tokenPolicy: {
    accessTokenTtlSeconds: number;
    refreshTokenTtlSeconds: number;
    codeTtlSeconds: number;
    sessionIdleTtlSeconds: number;
    sessionMaxTtlSeconds: number;
  };
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireNumber: boolean;
    requireSymbol: boolean;
    /** How many previous credentials may not be reused. Zero means no history is kept. */
    historyDepth: number;
  };
  /**
   * How the sign-in page renders for this realm.
   *
   * This is what lets the login page look like the relying party's own page without the identity
   * console becoming that application. A client record may override it, which is how every product
   * that does this handles it.
   */
  branding: {
    displayName: string;
    logoUri?: string;
    primaryColor?: string;
    backgroundStyle?: string;
  };
  /**
   * Whether impersonation may be issued in this realm at all.
   *
   * The simulator exchanges a token to act as a demo persona. Gating it on the REALM rather than on
   * an environment means a production realm cannot issue one no matter how the process was started.
   */
  demoMode: boolean;
  meta: Meta;
}

/** Resolves a name or an alias to a realm. Replaces the platform's hardcoded alias resolver. */
export function matchesRealmName(realm: Pick<RealmRecord, 'name' | 'aliases'>, candidate: string): boolean {
  const wanted = candidate.trim().toLowerCase();
  return realm.name.toLowerCase() === wanted
    || realm.aliases.some((alias) => alias.toLowerCase() === wanted);
}
