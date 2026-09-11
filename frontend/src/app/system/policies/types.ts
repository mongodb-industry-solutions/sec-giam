/** The policy shapes the authority returns. Mirrors the contract, and nothing is derived on the client. */

/**
 * The whole condition vocabulary, mirrored from the contract.
 *
 * Identity context only: assurance, network, time, tenant, attestation. The editor offers these and
 * nothing else, and the API refuses anything else, so the two cannot drift into disagreement about
 * what a policy is allowed to say.
 */
export const CONDITION_KEYS = [
  'assuranceAtLeast',
  'ipInRange',
  'timeOfDayUtc',
  'tenantIs',
  'attestationRequired',
  'heldRole',
  'heldPermission',
] as const;

export type ConditionKey = (typeof CONDITION_KEYS)[number];

export interface PolicyCondition {
  assuranceAtLeast?: 'aal1' | 'aal2' | 'aal3';
  ipInRange?: string[];
  /** UTC hours, half open. A `to` before `from` wraps midnight. */
  timeOfDayUtc?: { from: number; to: number };
  tenantIs?: string;
  attestationRequired?: boolean;
  /** At least one of these, by role name. Independent of `heldPermission`: either, neither or both. */
  heldRole?: string[];
  /** Every one of these, `resource:action`. Independent of `heldRole`. */
  heldPermission?: string[];
}

/**
 * One way of naming "one or several things", used identically by every section of a policy:
 * `resource`, `permission`, `principal` and `role`. `ids` is the fast path, matched by a plain
 * indexed lookup. `pattern` is a regular expression (compiled with RE2, so it is guaranteed
 * linear-time and cannot hang a decision), for the rare policy that describes a shape rather than
 * listing every member it covers. `ids` wins when both are given, rather than the write being
 * refused.
 */
export interface Selector {
  ids?: string[];
  pattern?: string;
}

export interface PolicyObligation {
  type: string;
  severity?: 'low' | 'medium' | 'high';
}

/**
 * One policy: one effect, over one resource pattern, under conditions.
 *
 * FLAT since v40 (ADR section 7): a policy used to hold a list of statements, and every one ever
 * seeded carried exactly one, so the nesting bought nothing and cost the question of what it means
 * for two statements in one policy to disagree. Two rules are two policies now.
 */
export interface PolicySummary {
  policyId: string;
  name: string;
  version: number;
  status: 'draft' | 'active' | 'retired';
  /** Whether this policy prohibits. The first thing a reviewer wants to know. */
  effect: 'allow' | 'deny';
  /** Carried on the summary, not only the detail: a resource's own screen asks "which policies
   * govern me" and needs this to decide, without a round trip per policy to find out. */
  resource: Selector;
  /** `resolvedPermissions.length`: what this policy concretely covers right now, roles expanded. */
  permissionCount: number;
  conditionCount: number;
  /** False while drafted, retired, or dated ahead, so a list shows what actually decides today. */
  inEffect: boolean;
  created?: string;
  lastModified?: string;
}

export interface PolicyDetail extends PolicySummary {
  /** What an author added directly, `resource:action`. Never mutated by a role reference. */
  permission: Selector;
  /** Roles whose current, expanded grants are folded into `resolvedPermissions`. Provenance only:
   * the decision engine never reads this, only what it already resolved to. */
  role?: Selector;
  /** Who this governs, by subject id or by pattern. Absent matches anyone. */
  principal?: Selector;
  /** The actual, flat set this policy is evaluated against: `permission` union every permission
   * every role in `role` currently grants. */
  resolvedPermissions: string[];
  conditions: PolicyCondition[];
  obligations?: PolicyObligation[];
  approvedBy?: string;
  /** Written down and not yet in force until this moment passes. */
  effectiveFrom?: string;
  reason?: string;
}

/** Which document, which version, and which line of it decided. */
export interface DecidingStatement {
  policyId: string;
  name: string;
  version: string;
  statementIndex: number;
  effect: 'allow' | 'deny';
}

export interface EvaluatorOpinion {
  name: string;
  /** Null is no opinion, which is not a denial. The distinction is the point of the trace. */
  effect: 'allow' | 'deny' | null;
  reason?: string;
  source?: string;
}

/** The decision endpoint's answer: an AuthZEN-shaped boolean, with the working in the context. */
export interface DecisionResult {
  decision: boolean;
  context: {
    effect: 'allow' | 'deny';
    reason: string;
    source?: string;
    policy?: DecidingStatement;
    evaluators: EvaluatorOpinion[];
    subjectId?: string;
    evaluatedAt?: string;
  };
}

export const ASSURANCE_LEVELS = ['aal1', 'aal2', 'aal3'] as const;

/**
 * One resource server as the catalog reports it, with the resource types it declares.
 *
 * Carried here rather than re-declared per screen: a policy names a resource by NAME, and turning
 * that name into something a reader recognises (its display name, which server declares it, what
 * may be done to it) is the same job on every screen that shows a policy's targets.
 */
export interface ResourceServerCatalogEntry {
  resourceId: string;
  name: string;
  displayName?: string;
  resources: Array<{
    resourceId: string;
    name: string;
    displayName?: string;
    description?: string;
    actions?: string[];
  }>;
}

/** A resource type, resolved from its name for display. */
export interface ResourceCatalogEntry {
  resourceId: string;
  displayName?: string;
  description?: string;
  actions: string[];
  /** The resource server that declares it, so `roles` reads as "Authority / roles". */
  serverName: string;
}
