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
] as const;

export type ConditionKey = (typeof CONDITION_KEYS)[number];

export interface PolicyCondition {
  assuranceAtLeast?: 'aal1' | 'aal2' | 'aal3';
  ipInRange?: string[];
  /** UTC hours, half open. A `to` before `from` wraps midnight. */
  timeOfDayUtc?: { from: number; to: number };
  tenantIs?: string;
  attestationRequired?: boolean;
}

export interface PolicyResource {
  type: string;
  /** `*` alone, or a trailing `*` for a prefix. Never a regular expression. */
  pattern: string;
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
  permissionCount: number;
  conditionCount: number;
  /** False while drafted, retired, or dated ahead, so a list shows what actually decides today. */
  inEffect: boolean;
  attachedTo: string[];
  created?: string;
  lastModified?: string;
}

export interface PolicyDetail extends PolicySummary {
  /** Full permission strings, `resource:action`. The same spelling a role and a token use. */
  permissions: string[];
  resource: PolicyResource;
  /** Subject patterns. `*` alone, or a trailing `*` for a prefix. Absent matches anyone. */
  principals?: string[];
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
