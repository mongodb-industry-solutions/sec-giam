import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A principal authorising another to act on its behalf.
 *
 * Distinct from a grant, and the distinction is the whole point. A grant is a person letting an
 * application use scopes on their account. A delegation is a person letting an AGENT act for them,
 * bounded by purpose, and it must remain visible per hop: the token says `sub` is the person and
 * `act` names the agent, so a downstream system can see both.
 *
 * That is why delegation is the default and impersonation the exception. Impersonation replaces the
 * subject, and every system downstream then sees only the person: the agent's part in what happened
 * is gone, and no amount of logging elsewhere reconstructs it.
 */
export interface DelegationRecord extends Scoped {
  delegationId: string;
  /** The principal whose authority is being lent. */
  principalSubjectId: string;
  /** The principal receiving it. Named for the common case; any principal may hold one. */
  agentId: string;

  /**
   * What it is FOR, in the consuming application's own vocabulary.
   *
   * Required rather than optional. An unbounded delegation is indistinguishable from handing over
   * the account, and the reason it was granted is the only thing that makes a later review possible.
   */
  purpose: string;

  /** Never wider than what the delegating principal holds; intersected at issuance, never unioned. */
  scope: string[];

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

  /** Not before now, where a delegation is arranged ahead of the work it is for. */
  notBefore?: string;
  /** What was relied on when granting it, in the granting system's own terms. */
  evidenceRef?: string;
  /** The permissions the delegate may exercise, if narrower still than the scope. */
  permissions?: Array<{ resource: string; action: string }>;

  /**
   * How many further hops this may be delegated onward.
   *
   * Zero means the delegate acts and cannot pass it on. Bounding it is what stops a chain growing
   * until nobody can say who authorised the last link.
   */
  maxDepth: number;

  /**
   * Bound to a single task, for authority worth constraining that tightly.
   *
   * A token minted for one transaction cannot be reused for another, which is the difference between
   * "may move money for this payment" and "may move money".
   */
  transactionId?: string;

  status: 'active' | 'revoked' | 'expired';
  grantedAt: string;
  /**
   * Required, not optional.
   *
   * A delegation with no end is one nobody revisits. Every one of these expires, and renewing it is a
   * decision somebody makes again rather than one made once and forgotten.
   */
  expiresAt: string;
  revokedAt?: string;
  revocationReason?: string;
  lastUsedAt?: string;
  meta: Meta;
}

/** Whether this delegation may still be exercised, before anything is issued against it. */
export function isExercisable(
  delegation: Pick<DelegationRecord, 'status' | 'expiresAt'>,
  now = new Date(),
): boolean {
  return delegation.status === 'active' && Date.parse(delegation.expiresAt) > now.getTime();
}

/**
 * Intersects the requested scope with what the delegation allows.
 *
 * Rule 1 of the multi-hop rules, as a function rather than as a convention: a downstream token can
 * never broaden the authority of the token it came from. Written here so every caller gets the same
 * answer, because a union performed once anywhere defeats the rule everywhere.
 */
export function narrowScope(held: string[], requested: string[]): string[] {
  if (requested.length === 0) return [...held];
  const available = new Set(held);
  return requested.filter((scope) => available.has(scope));
}

/**
 * The delegation chain, as it appears in the token.
 *
 * Appended to, never truncated or rewritten. The chain is the only record of who authorised the last
 * link, and an intermediate hop that could edit it could hide its own involvement.
 */
export interface DelegationHop {
  subjectId: string;
  clientId?: string;
  delegationId?: string;
}

/** How deep a chain already runs. Compared against the realm's bound before another hop is allowed. */
export function chainDepth(actor: { actor?: unknown } | undefined): number {
  let depth = 0;
  let current = actor as { actor?: { actor?: unknown } } | undefined;
  while (current) {
    depth += 1;
    current = current.actor as { actor?: { actor?: unknown } } | undefined;
  }
  return depth;
}
