import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A subject consenting, optionally purpose bound.
 *
 * This is the OAuth half of a word that names two different things. The other half, consent to
 * access an account under payment-services regulation, is regulated business data that belongs to
 * the institution holding the account and is never modelled here. The authority has no business
 * knowing an account exists, so it cannot represent a consent to reach one even if asked.
 *
 * A DELEGATION IS A GRANT WITH A PURPOSE, per ADR section 11, and that is why the two used to be
 * separate collections and no longer are. Both record the same fact, that a subject agreed to
 * something being done in their name; both are read by the same question, "what has this subject
 * authorised and is it still exercisable"; and both are revoked the same way. Keeping them apart
 * invited the question of which one a given consent lived in, and answering it wrongly meant a
 * revocation that missed.
 *
 * The presence of `purpose` is the discriminator, as the ADR frames it. An unbounded delegation is
 * indistinguishable from handing over the account, so purpose is what makes the difference visible.
 */
export interface GrantRecord extends Scoped {
  grantId: string;
  /** The principal consenting, whose authority is being relied on or lent. */
  subjectId: string;
  /** The client the consent is for. */
  clientId: string;

  /**
   * The principal RECEIVING lent authority, where one is named.
   *
   * Present on a delegation and absent on an ordinary consent, because consenting to an application
   * reading your profile hands authority to the application, while delegating hands it to somebody
   * who then acts through an application.
   */
  agentSubjectId?: string;

  /** Space-delimited, matching the token request that will be judged against it. */
  scope: string;
  status: 'active' | 'revoked' | 'expired';
  grantedAt: string;
  revokedAt?: string;
  revocationReason?: string;
  lastUsedAt?: string;

  /**
   * What it is FOR, in the consuming application's own vocabulary.
   *
   * Its presence makes this a delegation. Required for one, because the reason it was granted is the
   * only thing that makes a later review possible, and absent on an ordinary consent, where the
   * scope already says everything there is to say.
   */
  purpose?: string;

  /**
   * Limits that are not expressible as a scope.
   *
   * A delegation to move money is not the same as one to move money up to a limit, and a scope
   * cannot say the difference. These are checked by the consuming application, which is the only
   * party that knows what a value or a resource means.
   */
  constraints?: {
    maxValue?: number;
    allowedResources?: string[];
    allowedTools?: string[];
  };

  /**
   * When it stops. Optional for a consent, and in practice always set for a delegation.
   *
   * A delegation with no end is one nobody revisits, so renewing it should be a decision somebody
   * makes again rather than one made once and forgotten. An ordinary consent legitimately stands
   * until it is withdrawn.
   */
  expiresAt?: string;
  /** Not before now, where authority is arranged ahead of the work it is for. */
  notBefore?: string;
  /** What was relied on when granting it, in the granting system's own terms. */
  evidenceRef?: string;

  /** Full permission strings, where the delegate may exercise less than the scope allows. */
  permissions?: string[];

  /**
   * How many further hops this may be delegated onward.
   *
   * Zero means the delegate acts and cannot pass it on. Bounding it is what stops a chain growing
   * until nobody can say who authorised the last link.
   */
  maxDepth?: number;

  /**
   * Bound to a single task, for authority worth constraining that tightly.
   *
   * A token minted for one transaction cannot be reused for another, which is the difference between
   * "may move money for this payment" and "may move money".
   */
  transactionId?: string;

  meta: Meta;
}

export function grantedScopes(grant: Pick<GrantRecord, 'scope'>): string[] {
  return grant.scope.split(' ').filter(Boolean);
}

/** Whether a grant still covers everything a request asks for. A partial grant is not a grant. */
export function covers(grant: Pick<GrantRecord, 'scope' | 'status'>, requested: string[]): boolean {
  if (grant.status !== 'active') return false;
  const held = new Set(grantedScopes(grant));
  return requested.every((scope) => held.has(scope));
}

/** A grant carrying a purpose is a delegation. The one distinction the merged record makes. */
export function isDelegation(grant: Pick<GrantRecord, 'purpose'>): boolean {
  return typeof grant.purpose === 'string' && grant.purpose.length > 0;
}

/**
 * Whether this may still be exercised, before anything is issued against it.
 *
 * Every clause fails CLOSED. A grant that is not active, has not started, or has lapsed grants
 * nothing, and the order of the checks does not change the answer.
 */
export function isExercisable(
  grant: Pick<GrantRecord, 'status' | 'expiresAt' | 'notBefore'>,
  now = new Date(),
): boolean {
  if (grant.status !== 'active') return false;
  const at = now.getTime();
  if (grant.notBefore && Date.parse(grant.notBefore) > at) return false;
  return !grant.expiresAt || Date.parse(grant.expiresAt) > at;
}

/**
 * The scope a delegated hop may carry: never wider than what is held.
 *
 * Intersected, never unioned. A hop that could add a scope would let a chain end up broader than
 * the authority it started from, which is the failure delegation depth limits exist to prevent.
 */
export function narrowScope(held: string[], requested: string[]): string[] {
  const available = new Set(held);
  const asked = requested.filter((scope) => available.has(scope));
  return asked.length > 0 ? asked : held;
}

/*
 * `chainDepth` and `DelegationHop` lived here and are gone.
 *
 * `chainDepth` walked an actor chain through an untyped `{ actor?: unknown }`, duplicating
 * `actorChainDepth` in the oauth module, which walks the same chain with the real type. Two
 * implementations of one traversal is how the two disagree about depth after the claim's member
 * names change, which is exactly what happened: this one still looked for `actor` after the claim
 * became RFC 8693's `act`, and the untyped parameter is why the compiler could not say so.
 *
 * `DelegationHop` was never referenced by anything.
 */
