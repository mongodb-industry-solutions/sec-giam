import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * ONE AUTHENTICATION PATH INTO A REALM, local or federated.
 *
 * Widened from "an upstream identity provider" by ADR section 3, and the widening is the point. The
 * local authentication rules used to live on the realm while external providers lived here, which
 * was two places describing the same thing: how a subject proves who they are. A realm's own
 * directory is now ONE DOMAIN AMONG OTHERS rather than a special case with its own home.
 *
 * That is also what lets this authority sit in front of an upstream. A realm with three domains
 * offers three ways in, and the sign-in screen is a projection of that list rather than a branch on
 * whether any providers happen to be configured.
 *
 * Naming note: the ADR calls this discriminator `kind`. It is `protocol` here, with the same
 * meaning and the same values, because the name is already part of a published port contract and
 * renaming it would ripple through the port and its consumers for no gain. `internal` is the ADR's
 * `local`.
 *
 * Adding a third-party provider is still this record plus a claim mapping: no application code, no
 * deployment, no restart. That is the whole argument for brokering rather than every application
 * implementing OIDC and SAML again.
 */
export interface DomainRecord extends Scoped {
  providerId: string;
  /** Slug, unique inside the realm. */
  name: string;
  displayName: string;
  protocol: 'internal' | 'oidc' | 'saml' | 'ldap' | 'spiffe';
  /** Which port implementation handles it. Configuration on the record, never an environment read. */
  adapter: string;
  enabled: boolean;
  /** Shown when a provider is visible but not yet usable, rather than failing after it is chosen. */
  notice?: string;
  config: {
    issuer?: string;
    clientId?: string;
    clientSecretRef?: string;
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    jwksUri?: string;
    scopes?: string[];
    tenant?: string;
    /** Home-realm discovery: an entered email domain resolves to this provider. */
    emailDomains?: string[];
    [setting: string]: unknown;
  };
  /**
   * Upstream claim to local role.
   *
   * The mapping is data because the alternative is an application learning what an upstream group is
   * called, which is exactly the coupling brokering removes.
   */
  claimMappings: Array<{ claim: string; value: string; roleName: string }>;

  /**
   * How a subject proves who they are on THIS path. Moved off the realm by ADR section 3.
   *
   * It sat on the realm, which meant a realm offering both its own directory and an upstream had
   * one password policy describing one of them and nothing describing the other. Rules about
   * proving identity belong to the path that does the proving.
   *
   * Present for `internal`, and meaningless for a federated path where the upstream sets its own.
   */
  authentication?: {
    passwordPolicy?: {
      minLength: number;
      requireUppercase: boolean;
      requireNumber: boolean;
      requireSymbol: boolean;
      /** How many previous credentials may not be reused. Zero means no history is kept. */
      historyDepth: number;
    };
    /** The floor this path must reach. A path that cannot reach it should not be offered. */
    requiredAssurance?: 'aal1' | 'aal2' | 'aal3';
    mfaRequired?: boolean;
    lockout?: {
      /** Consecutive failures before the account is locked on this path. */
      maxAttempts: number;
      /** How long the lock holds. Zero means until an administrator lifts it. */
      forSeconds: number;
    };
  };

  /**
   * How many sessions a subject may hold at once through this path.
   *
   * On the DOMAIN and not on the realm or the client, because how many times you may be signed in
   * is an authentication rule. A realm with two domains applies each domain's limit to its own
   * sessions, counted per subject within the realm.
   *
   * Unlimited is the default, deliberately. `maxConcurrent: 1` for a person using a laptop, a phone
   * and a tablet produces constant eviction ping-pong; it belongs on high-assurance and
   * administrative paths, not everywhere.
   *
   * Eviction is a `deleteOne` on `session`, so it emits a revocation signal for free: an evicted
   * device learns it has been evicted rather than holding a valid token until it expires.
   */
  session?: {
    maxConcurrent: number | null;
    /** `refuse-new` is correct for a service account, where the existing session is the real one. */
    onExceed: 'evict-oldest' | 'refuse-new';
  };

  meta: Meta;
}

/** Why a password was refused. Named individually, so a caller can say which rule it broke. */
export type PasswordRefusal =
  | { rule: 'minLength'; required: number }
  | { rule: 'requireUppercase' }
  | { rule: 'requireNumber' }
  | { rule: 'requireSymbol' };

/**
 * Checks a password against the path's policy. Empty means it passed.
 *
 * v40 P11.10: the policy was seeded and NEVER ENFORCED. `minLength: 8` sat in the database and
 * nothing compared a password to it, so the field described a control that did not exist. A policy
 * nobody checks is worse than no policy, because it is read as a control during a review.
 *
 * Returns every rule broken rather than the first, so a person is told what to fix once instead of
 * discovering the rules one refusal at a time.
 *
 * A path with NO policy passes everything. That is the honest reading: a federated domain's rules
 * belong to its upstream, and inventing a floor here would apply this authority's opinion to a
 * password it never sees.
 */
export function checkPassword(
  policy: NonNullable<NonNullable<DomainRecord['authentication']>['passwordPolicy']> | null | undefined,
  password: string,
): PasswordRefusal[] {
  if (!policy) return [];
  const broken: PasswordRefusal[] = [];
  if (password.length < policy.minLength) {
    broken.push({ rule: 'minLength', required: policy.minLength });
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) broken.push({ rule: 'requireUppercase' });
  if (policy.requireNumber && !/[0-9]/.test(password)) broken.push({ rule: 'requireNumber' });
  // Anything that is not a letter, a digit or whitespace. Deliberately broad: a narrow list would
  // refuse a perfectly good password for containing a character nobody thought to allow.
  if (policy.requireSymbol && !/[^A-Za-z0-9\s]/.test(password)) broken.push({ rule: 'requireSymbol' });
  return broken;
}

/** One sentence a person can act on, from the rules they broke. */
export function describeRefusals(refusals: PasswordRefusal[]): string {
  return refusals.map((refusal) => {
    switch (refusal.rule) {
      case 'minLength': return `at least ${refusal.required} characters`;
      case 'requireUppercase': return 'an upper-case letter';
      case 'requireNumber': return 'a digit';
      default: return 'a symbol';
    }
  }).join(', ');
}

/** The password rules in force on a path, or null where the upstream owns them. */
export function passwordPolicyOf(domain: Pick<DomainRecord, 'protocol' | 'authentication'>) {
  if (domain.protocol !== 'internal') return null;
  return domain.authentication?.passwordPolicy ?? null;
}

/**
 * What to do when a subject already holds the limit on this path.
 *
 * Null means unlimited, which is not the same as zero: zero would mean no session may be opened at
 * all, and returning "allowed" for an unconfigured domain is what keeps unlimited the default.
 */
export function concurrentSessionRule(
  domain: Pick<DomainRecord, 'session'>,
): { limit: number | null; onExceed: 'evict-oldest' | 'refuse-new' } {
  return {
    limit: domain.session?.maxConcurrent ?? null,
    onExceed: domain.session?.onExceed ?? 'evict-oldest',
  };
}
