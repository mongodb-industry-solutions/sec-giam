import { RealmRecord } from './realm.model';
import { DomainRecord } from './domain.model';

/**
 * What a new realm starts with, shared by the seeder and by runtime realm creation so the two can
 * never drift into two different ideas of what a freshly provisioned realm looks like.
 */

export const DEFAULT_TOKEN_POLICY: RealmRecord['tokenPolicy'] = {
  /**
   * Five minutes, and this number IS the revocation objective.
   *
   * An access token is verified against the published key set without touching the database, which
   * is what keeps this authority off the hot path. The cost is that revoking a session cannot reach
   * a token already issued, so the worst case propagation is exactly this lifetime. Fifteen minutes
   * made that window three times longer for no benefit that was ever written down.
   */
  accessTokenTtlSeconds: 300,
  refreshTokenTtlSeconds: 2_592_000,
  codeTtlSeconds: 120,
  sessionIdleTtlSeconds: 3_600,
  sessionMaxTtlSeconds: 43_200,
};

/**
 * The rules for proving identity against a realm's OWN directory.
 *
 * On the local domain rather than on the realm, because that is the path they describe. A realm that
 * also federates has an upstream setting its own, and the two no longer have to pretend to be one.
 */
export const DEFAULT_LOCAL_AUTHENTICATION: NonNullable<DomainRecord['authentication']> = {
  passwordPolicy: {
    minLength: 8,
    requireUppercase: false,
    requireNumber: false,
    requireSymbol: false,
    historyDepth: 0,
  },
};

/**
 * The slug every realm's own directory is registered under.
 *
 * `local` said where the directory was rather than what it is, and it read as a developer's word
 * for "not the real one" on a screen a customer sees. This is the realm's OWN directory: the
 * credentials it holds, the policy it enforces and the only path anybody can self-register into.
 *
 * Realm neutral on purpose. Every realm registers one of these, so a slug naming one product would
 * be wrong in the other realm the moment there are two.
 */
export const LOCAL_DOMAIN_NAME = 'atlas-id';

/**
 * The realm's own directory, built the one way both the seeder and runtime realm creation agree on.
 *
 * A pure builder rather than a write itself: the two call sites differ in how they choose the
 * domain's id (a stable one from a fixture's realmId, a random one at creation time) and in whether
 * they upsert or insert, and neither of those belongs in the shape every realm's directory takes.
 */
export function localDomainRecord(input: {
  domainId: string;
  realmId: string;
  tenantId: string;
  realmDisplayName: string;
  /** Overrides the generic `"{realm} directory"` default, for a realm that wants its own directory to read as its own product rather than the platform's generic label. */
  domainDisplayName?: string;
  registration?: { selfServiceEnabled: boolean; autoApprove: boolean };
  authentication?: NonNullable<DomainRecord['authentication']>;
}): Omit<DomainRecord, 'meta'> {
  return {
    realmId: input.realmId,
    tenantId: input.tenantId,
    domainId: input.domainId,
    name: LOCAL_DOMAIN_NAME,
    displayName: input.domainDisplayName ?? `${input.realmDisplayName} directory`,
    protocol: 'internal',
    adapter: 'internal',
    enabled: true,
    config: {},
    claimMappings: [],
    authentication: { ...DEFAULT_LOCAL_AUTHENTICATION, ...input.authentication },
    // Unlimited by default: one session per subject produces constant eviction for a person using
    // a laptop, a phone and a tablet.
    session: { maxConcurrent: null, onExceed: 'evict-oldest' },
    // Self-registration lives HERE and not on the realm (ADR-002). Closed unless asked for: the
    // internal directory is the only path anybody can join through, so it is the only one this
    // can describe.
    registration: input.registration ?? { selfServiceEnabled: false, autoApprove: false },
  };
}
