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

export interface PolicyStatement {
  effect: 'allow' | 'deny';
  principals?: string[];
  actions?: string[];
  resources?: string[];
  condition?: PolicyCondition;
  reason?: string;
}

export interface PolicySummary {
  policyId: string;
  name: string;
  version: string;
  enabled: boolean;
  statementCount: number;
  /** How many statements prohibit. A policy that denies and one that only permits are different objects. */
  denyCount: number;
  conditionCount: number;
  attachedTo: string[];
  created?: string;
  lastModified?: string;
}

export interface PolicyDetail extends PolicySummary {
  statements: PolicyStatement[];
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
