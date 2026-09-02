import { Meta, Scoped } from '../../../shared/models/base.model';
import { config, ClientEnforcementMode } from '../../../config';

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
  /**
   * NO passwordPolicy here any more. It moved to the local `domain` (ADR section 3, P8.2).
   *
   * It sat on the realm while external providers carried their own rules, which was two places
   * describing one thing: how a subject proves who they are. A realm offering both its own
   * directory and an upstream had one policy describing one of them and nothing describing the
   * other. The realm keeps only what is genuinely issuer level: the issuer URL, key references,
   * token lifetimes, branding and registration policy.
   */
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
  /**
   * What happens to a client that is not registered here.
   *
   * Per realm rather than per process, because onboarding is something a single realm goes through
   * while the others beside it are already established. Absent means the deployment default, which
   * is `strict`. `soft` admits an unregistered client with reduced authority, records every
   * admission and reports the realm as degraded; it relaxes NOT BEING REGISTERED and nothing else,
   * so a wrong secret, a revoked client or a mismatched redirect is still refused.
   */
  clientEnforcement?: ClientEnforcementMode;
  meta: Meta;
}

/** The mode actually in force for a realm: its own, or the deployment default. */
export function enforcementFor(realm: Pick<RealmRecord, 'clientEnforcement'>): ClientEnforcementMode {
  return realm.clientEnforcement ?? config.app.clientEnforcement;
}

/** Resolves a name or an alias to a realm. Replaces the platform's hardcoded alias resolver. */
export function matchesRealmName(realm: Pick<RealmRecord, 'name' | 'aliases'>, candidate: string): boolean {
  const wanted = candidate.trim().toLowerCase();
  return realm.name.toLowerCase() === wanted
    || realm.aliases.some((alias) => alias.toLowerCase() === wanted);
}
