import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * Conditional authorization statements, evaluated after roles.
 *
 * A JSON document per statement set, which is the shape a document database stores natively and the
 * reason this is not a join across three tables.
 *
 * The conditions are IDENTITY context only: time, network, assurance, tenant, ownership, attestation
 * state. Not business materiality. A condition naming an amount or a business threshold is a defect,
 * because that judgement belongs to the system that can see the business inputs, and an identity
 * authority making it would be answering a question it cannot observe.
 */
export interface PolicyCondition {
  assuranceAtLeast?: 'aal1' | 'aal2' | 'aal3';
  ipInRange?: string[];
  /** UTC hours, half open. `to` before `from` means the window wraps midnight. */
  timeOfDayUtc?: { from: number; to: number };
  tenantIs?: string;
  attestationRequired?: boolean;
}

/**
 * The whole condition vocabulary, as data.
 *
 * Declared once so the request schema, the administrative service and the console editor cannot
 * disagree about what a policy may say. Adding an entry here is the only way to widen the language,
 * which makes widening it a visible act rather than a field somebody let through.
 */
export const POLICY_CONDITION_KEYS = [
  'assuranceAtLeast',
  'ipInRange',
  'timeOfDayUtc',
  'tenantIs',
  'attestationRequired',
] as const;

export type PolicyConditionKey = (typeof POLICY_CONDITION_KEYS)[number];

export interface PolicyStatement {
  effect: 'allow' | 'deny';
  principals?: string[];
  actions?: string[];
  resources?: string[];
  condition?: PolicyCondition;
  /** Carried into the decision, because a decision a log cannot explain is not auditable. */
  reason?: string;
}

export interface PolicyRecord extends Scoped {
  policyId: string;
  name: string;
  version: string;
  statements: PolicyStatement[];
  attachedTo?: string[];
  enabled: boolean;
  meta: Meta;
}

/**
 * Matches a pattern against a value.
 *
 * `*` alone matches anything; a trailing `*` matches a prefix. Deliberately not a full glob or a
 * regular expression: a policy pattern that can express arbitrary matching is a policy nobody can
 * review, and review is the point of writing one down.
 */
export function matchesPattern(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return value.startsWith(pattern.slice(0, -1));
  return pattern === value;
}
