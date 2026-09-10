import RE2 from 're2';
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
  /**
   * The subject must hold at least one of these roles, by name. Membership, exactly as NIST SP
   * 800-162 names role among the subject attributes ABAC narrows on, and as AWS Cedar expresses it
   * (`principal in Role::X`): not a second decision engine, one more thing this one may ask about
   * who is asking.
   */
  heldRole?: string[];
  /**
   * The subject must hold every one of these permissions, `resource:action`. Independent of
   * `heldRole` rather than an alternative to it: a policy may name one, the other, or both together
   * for a narrower requirement than either alone states.
   */
  heldPermission?: string[];
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
  'heldRole',
  'heldPermission',
] as const;

export type PolicyConditionKey = (typeof POLICY_CONDITION_KEYS)[number];

/**
 * What a policy obliges the enforcing side to DO when it allows something.
 *
 * Carried rather than acted on here: this authority decides, and the resource server is what can
 * actually raise an alert or demand a second signature. Recording the obligation is what makes the
 * decision auditable without this service pretending to enforce it.
 */
export interface PolicyObligation {
  type: string;
  severity?: 'low' | 'medium' | 'high';
}

/**
 * One policy: one effect, over one resource pattern, under conditions.
 *
 * FLAT, per ADR section 7, rather than a list of statements. Every policy in the seed carried
 * exactly one statement, so the nesting bought nothing and cost the obvious question of what it
 * means when two statements in one policy disagree. Two rules are now two policies, which is also
 * what makes each one separately versionable and separately approvable.
 *
 * Two fields go BEYOND the ADR's shape, because dropping each would remove a capability rather
 * than simplify one:
 *
 * - `principals`, because a policy that cannot name who it applies to can only be global, and
 *   "this rule, for these subjects" is the ordinary case for a prohibition.
 * - `reason`, because a decision a log cannot explain is not auditable, and the reason is the
 *   difference between "denied" and "denied by this policy, because the assurance was too low".
 */
export interface PolicyRecord extends Scoped {
  policyId: string;
  name: string;
  /** A NUMBER, because it is compared and incremented. As a string, '10' sorts below '9'. */
  version: number;
  /** `active` is evaluated. Anything else is not, which is what replaces the old `enabled` flag. */
  status: 'draft' | 'active' | 'retired';

  effect: 'allow' | 'deny';
  /** Full permission strings this policy governs, `resource:action`. */
  permissions: string[];
  /**
   * What it governs, by identity or by shape, never both at once.
   *
   * `names` is the fast path: one or several resources named exactly, matched by a plain indexed
   * equality lookup. `pattern` is the slow path: a regular expression, for the rare policy that
   * needs to describe a shape rather than list every resource it covers, evaluated in memory
   * against the (typically small) set of policies that chose it rather than against the whole
   * realm. Combining them would be ambiguous about which one actually decided, so exactly one is
   * required.
   */
  resource: { names?: string[]; pattern?: string };

  principals?: string[];
  /** ALL must hold. An empty list is a policy with no conditions, which is not a policy that never applies. */
  conditions: PolicyCondition[];
  obligations?: PolicyObligation[];

  approvedBy?: string;
  effectiveFrom?: string;
  /** Carried into the decision, because a decision a log cannot explain is not auditable. */
  reason?: string;
  meta: Meta;
}

/** Whether a policy is one the engine should evaluate at all, at this moment. */
export function isInEffect(policy: Pick<PolicyRecord, 'status' | 'effectiveFrom'>, now = new Date()): boolean {
  if (policy.status !== 'active') return false;
  // A policy dated into the future is written down and not yet in force, which is a normal state
  // for something that had to be approved before it applied.
  return !policy.effectiveFrom || Date.parse(policy.effectiveFrom) <= now.getTime();
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

/**
 * Compiled once per distinct pattern string, never per request. A policy's pattern does not change
 * between decisions, so recompiling it on every evaluation would pay a fixed cost for no reason;
 * the cache key is the pattern text itself, so two policies that happen to write the same pattern
 * share one compiled matcher.
 */
const compiledResourcePatterns = new Map<string, RE2>();

function compiledPattern(pattern: string): RE2 {
  let compiled = compiledResourcePatterns.get(pattern);
  if (!compiled) {
    compiled = new RE2(pattern);
    compiledResourcePatterns.set(pattern, compiled);
  }
  return compiled;
}

/**
 * Whether a policy's `resource` selector covers the resource a request names.
 *
 * RE2, not the engine built into the language: it guarantees linear-time matching for any pattern
 * that compiles, so a policy author's regular expression can never make a decision hang the way a
 * catastrophic-backtracking pattern would with `RegExp`. That guarantee is the reason a real
 * regular expression is safe to accept here at all.
 */
export function resourceApplies(resource: PolicyRecord['resource'], requested: string): boolean {
  if (resource.names?.length) return resource.names.includes(requested);
  if (resource.pattern) return compiledPattern(resource.pattern).test(requested);
  return false;
}
