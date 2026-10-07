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
  /**
   * Absolute issuer URL, the `iss` of every token. DERIVED from the realm name and this deployment's
   * public origin each time a record is read, never stored: a stored one would pin the database to
   * the environment that wrote it, and the database is shared between environments.
   */
  issuer: string;
  enabled: boolean;
  /**
   * Alternative names a caller may use on the wire.
   *
   * Data rather than a constant, which is the point: the platform's `local` alias used to be a
   * hardcoded special case in a resolver, and here it is a value on the record it belongs to.
   */
  aliases: string[];
  /**
   * A line of copy under the whole sign-in screen, about the REALM.
   *
   * Deliberately not the same field as `DomainRecord.notice`, which is rendered against one entry
   * in the domain picker and says why that path is unavailable or what it federates with. Two
   * notices can be shown at once because they are about different things; neither overrides the
   * other, and nothing should merge them.
   */
  notice?: string;
  /**
   * Self-registration moved to `domain.registration` in ADR-002.
   *
   * It described the internal directory while sitting on the realm, and nobody self-registers into
   * a federated upstream. Removed rather than deprecated: a setting readable from two places is one
   * that will disagree with itself.
   */
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
    /**
     * Present ONLY when the rendered label differs from `displayName`.
     *
     * It used to be seeded as a copy of `displayName` on every realm, which is two fields holding
     * one value and no rule for which wins once somebody edits one of them. Absent now means "the
     * realm's own name", so there is exactly one place to change it and an override is visible as
     * an override.
     */
    displayName?: string;
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
  /**
   * Whether a requested elevation needs a second principal to approve it before it is in force.
   *
   * Absent means yes, which is the safer default for a realm that has never said otherwise. Set to
   * `false` only for a realm whose own resource server already performs the review before ever
   * calling this endpoint: the platform's fraud investigation escalation is exactly that case (an L1
   * escalates, an L2 accepts, and accepting IS the review), and defaulting to `true` there made a
   * self-service, single-actor grant permanently `pendingApproval`, since nothing else in that flow
   * calls the separate `/approve` route a second reviewer would use.
   */
  requiresElevationApproval?: boolean;
  meta: Meta;
}

/** The mode actually in force for a realm: its own, or the deployment default. */
export function enforcementFor(realm: Pick<RealmRecord, 'clientEnforcement'>): ClientEnforcementMode {
  return realm.clientEnforcement ?? config.app.clientEnforcement;
}

/**
 * Whether a realm already in hand answers to this name. The same rule `RealmService.byName` asks
 * the database for, for a caller that has the record and should not go back for it.
 *
 * Case-insensitive, like the query and like the index behind it. Three places state this rule and
 * they must agree: this function, the `CASE_INSENSITIVE` collation on `name_unique` and `aliases`,
 * and the `byName` read that passes it.
 */
export function matchesRealmName(realm: Pick<RealmRecord, 'name' | 'aliases'>, candidate: string): boolean {
  const wanted = candidate.trim().toLowerCase();
  return realm.name.toLowerCase() === wanted
    || realm.aliases.some((alias) => alias.toLowerCase() === wanted);
}

/**
 * The label to render for a realm: its branding override where there is one, its own name otherwise.
 *
 * One function rather than the same `??` repeated at each render site, which is how the two fields
 * drifted into being copies of each other in the first place.
 */
export function brandLabel(realm: Pick<RealmRecord, 'displayName' | 'branding'>): string {
  return realm.branding.displayName ?? realm.displayName;
}
