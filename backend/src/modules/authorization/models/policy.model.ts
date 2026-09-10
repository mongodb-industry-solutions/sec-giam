import RE2 from 're2';
import { Meta, Scoped } from '../../../shared/models/base.model';
import { appendLog } from '../../../shared/services/logBuffer';

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
   *
   * Distinct from the policy's own `role` selector below: this asks what the REQUESTING subject
   * already holds. `role` asks what permissions a NAMED role grants, to fold into what this policy
   * itself governs. The two answer different questions and neither replaces the other.
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
 * One way of naming "one or several things", used identically by every section of a policy:
 * `resource`, `permission`, `principal` and `role`. `ids` is the fast path, a plain indexed
 * membership check. `pattern` is the slow path, a regular expression compiled with RE2 (so it is
 * guaranteed linear-time and cannot hang a decision), for the rare policy that describes a shape
 * rather than listing every member it covers.
 *
 * `ids` wins when both are given, rather than the write being refused: a pattern left behind
 * alongside a later, more specific `ids` list is dead weight, not a contradiction worth rejecting.
 */
export interface Selector {
  ids?: string[];
  pattern?: string;
}

/**
 * One policy: one effect, over one resource selector, under conditions.
 *
 * FLAT, per ADR section 7, rather than a list of statements. Every policy in the seed carried
 * exactly one statement, so the nesting bought nothing and cost the obvious question of what it
 * means when two statements in one policy disagree. Two rules are now two policies, which is also
 * what makes each one separately versionable and separately approvable.
 *
 * Every targeting section (`resource`, `permission`, `principal`, `role`) is the same `Selector`
 * shape, which is what lets one console screen present all four identically: a searchable,
 * paginated list, each entry linking to what it names.
 */
export interface PolicyRecord extends Scoped {
  policyId: string;
  name: string;
  /** A NUMBER, because it is compared and incremented. As a string, '10' sorts below '9'. */
  version: number;
  /** `active` is evaluated. Anything else is not, which is what replaces the old `enabled` flag. */
  status: 'draft' | 'active' | 'retired';

  effect: 'allow' | 'deny';

  /** What it governs, by resource id or by pattern. */
  resource: Selector;

  /**
   * The permissions an author added directly, `resource:action`. Never touched by anything but an
   * edit to this policy itself: the role-derived contribution lives in `resolvedPermissions`
   * instead, so a role changing shape elsewhere can never silently rewrite what this field says an
   * author asked for.
   */
  permission: Selector;

  /**
   * Roles whose CURRENT, expanded permissions (parents included, exactly as RBAC itself resolves
   * them) are unioned into `resolvedPermissions`. Provenance, not something the decision engine
   * reads: naming a role here is a convenience for building a permission set out of what that role
   * already grants, not a second targeting axis alongside `permission`.
   */
  role?: Selector;

  /** Who this governs. Absent matches anyone. */
  principal?: Selector;

  /**
   * The actual, flat set of `resource:action` strings this policy is evaluated against: `permission`
   * (its `ids`, or, absent those, every permission its `pattern` matches at decision time) UNION
   * every permission every role in `role` currently grants.
   *
   * Resolved once, when this policy is saved, and again whenever a role it names changes shape
   * (`PolicyAdminService.resyncRoleReferences`, called from role administration) — never resolved
   * live, mid-decision, which is what keeps the decision path free of an extra database read the
   * way token verification already is.
   */
  resolvedPermissions: string[];

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
 * Compiled once per distinct pattern string, never per request. A policy's pattern does not change
 * between decisions, so recompiling it on every evaluation would pay a fixed cost for no reason;
 * the cache key is the pattern text itself, so two policies (or two sections of the same kind) that
 * happen to write the same pattern share one compiled matcher.
 */
const compiledPatterns = new Map<string, RE2 | null>();

/**
 * `null` is cached too, not only a successful compile: a pattern that fails once fails the same way
 * every time, and retrying the same broken string on every request would repeat the cost AND the
 * log line for nothing.
 *
 * A pattern reaching here that does not compile should not happen: `validatePolicy` already refuses
 * one at every write path. It is caught anyway, because the one way it CAN still happen is a
 * document written before that check existed, and a leftover record is not a reason a request
 * naming an unrelated value should fail with a 500.
 */
function compiledPattern(pattern: string): RE2 | null {
  if (compiledPatterns.has(pattern)) return compiledPatterns.get(pattern)!;
  let compiled: RE2 | null;
  try {
    compiled = new RE2(pattern);
  } catch (error) {
    appendLog(
      `[${new Date().toISOString()}] ERROR a policy selector's pattern does not compile under RE2, `
      + `treated as matching nothing until fixed: ${JSON.stringify(pattern)} `
      + `(${error instanceof Error ? error.message : String(error)})`,
    );
    compiled = null;
  }
  compiledPatterns.set(pattern, compiled);
  return compiled;
}

/**
 * Whether a selector covers a value: `resource` against a resource name, `principal` against a
 * subject id, `role` against a role name. The one function every section shares, which is the
 * point: `ids` wins when present (a plain membership check), `pattern` only decides when `ids` is
 * absent or empty, and an absent selector entirely matches nothing here (a caller deciding "absent
 * means anyone", as `principal` does, checks that before calling this).
 *
 * RE2, not the engine built into the language: it guarantees linear-time matching for any pattern
 * that compiles, so a policy author's regular expression can never make a decision hang the way a
 * catastrophic-backtracking pattern would with `RegExp`.
 */
export function selectorApplies(selector: Selector | undefined, value: string): boolean {
  if (!selector) return false;
  if (selector.ids?.length) return selector.ids.includes(value);
  if (selector.pattern) return (compiledPattern(selector.pattern)?.test(value)) ?? false;
  return false;
}

/**
 * Whether a policy's permission targeting covers a requested `resource:action`.
 *
 * `resolvedPermissions` is the pre-resolved union of explicit `permission.ids` and every permission
 * every role in `role` currently grants (see `PolicyRecord.resolvedPermissions`), checked first as a
 * plain membership test. `permission.pattern` is checked live, exactly like `resource.pattern`,
 * only when `permission.ids` is absent (ids wins): a pattern reaching over the realm's permission
 * space is not pre-expanded into a fixed list the way a role's grants are, since a role's grants
 * change by an administrative act this system already hooks (`resyncRoleReferences`), while a
 * pattern's reach changes the moment ANY resource server registers a new action.
 */
export function permissionApplies(policy: Pick<PolicyRecord, 'resolvedPermissions' | 'permission'>, asked: string): boolean {
  if (policy.resolvedPermissions?.includes(asked)) return true;
  if (!policy.permission?.ids?.length && policy.permission?.pattern) {
    return (compiledPattern(policy.permission.pattern)?.test(asked)) ?? false;
  }
  return false;
}
