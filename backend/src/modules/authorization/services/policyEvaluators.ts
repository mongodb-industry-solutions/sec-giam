import { Db } from 'mongodb';
import type { PolicyEvaluator, AuthorizationRequest, AuthorizationDecision } from '../../../shared/ports';
import { POLICY_COLLECTION } from '../../../shared/models/collections';
import {
  PolicyRecord, PolicyCondition, isInEffect, selectorApplies, permissionApplies,
} from '../models/policy.model';
import { DecisionService } from './decision.service';

/**
 * Two evaluators, and the rule that combines them.
 *
 * DENY WINS, absolutely. Not "deny wins unless an explicit allow is more specific", not "the last
 * statement wins": if anything denies, the answer is deny. Any other combination rule means a
 * prohibition can be defeated by adding a permission somewhere else, which makes a prohibition
 * something nobody can rely on.
 *
 * Default deny underneath that: an absent decision is not an allow.
 */

let boundDb: Db | null = null;

export function bindPolicyEvaluators(db: Db): void {
  boundDb = db;
}

function database(): Db {
  if (!boundDb) throw new Error('Policy evaluators are not bound to a database');
  return boundDb;
}

/** Roles and the permissions they grant. The baseline every deployment has. */
export const rbacEvaluator: PolicyEvaluator = {
  name: 'rbac',

  async evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision | null> {
    const audience = typeof request.context.audience === 'string' ? request.context.audience : '';
    const decision = await new DecisionService(database())
      .check(request.realmId, request.subjectId, audience, request.resource, request.action);
    return decision;
  },
};

/**
 * Conditional statements evaluated after roles.
 *
 * Identity context only: time, network, assurance level, tenant, ownership, attestation state. NOT
 * business materiality. A policy naming an amount or a business threshold is a defect, because that
 * decision belongs to the system that understands the business, and an identity authority that
 * started making it would be answering a question it cannot see the inputs to.
 */
export const abacEvaluator: PolicyEvaluator = {
  name: 'abac',

  async evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision | null> {
    const policies = await database()
      .collection<PolicyRecord>(POLICY_COLLECTION)
      .find({
        realmId: request.realmId,
        tenantId: request.tenantId,
        status: 'active',
        // Pushed down rather than filtered in memory after the fact, because a realm with a very
        // large policy table must not read every active policy to decide about one resource. Named
        // exactly is a plain indexed equality lookup; a `pattern` policy cannot be excluded by an
        // index (it is a regular expression, not a value to compare against), so every one of those
        // is still a candidate and is resolved by `selectorApplies` below, in memory, against
        // however many policies actually chose that slower form rather than against all of them.
        $or: [
          { 'resource.ids': request.resource },
          { 'resource.pattern': { $exists: true } },
        ],
      }, { projection: { _id: 0 } })
      .toArray();

    // Resolved once, and only when some policy actually asks: `heldRole`/`heldPermission` are the
    // one condition pair that needs more than the request itself, and asking the decision point for
    // every request would cost a query even for a realm that never wrote one.
    const needsHolding = policies.some((policy) => (policy.conditions ?? [])
      .some((condition) => condition.heldRole?.length || condition.heldPermission?.length));
    const holding = needsHolding
      ? await new DecisionService(database()).effectivePermissions(
        request.realmId,
        request.subjectId,
        typeof request.context.audience === 'string' ? request.context.audience : '',
      )
      : null;

    let allow: AuthorizationDecision | null = null;

    for (const policy of policies) {
      // Status and the effective date are both checked here rather than only in the query, so a
      // policy approved for next Monday cannot decide anything today.
      if (!isInEffect(policy)) continue;
      if (!appliesTo(policy, request, holding)) continue;
      const deciding = {
        policyId: policy.policyId,
        name: policy.name,
        version: policy.version,
        effect: policy.effect,
      };
      if (policy.effect === 'deny') {
        // Returned immediately. Nothing later can overturn it, and evaluating on would only cost
        // time to reach the same answer.
        return {
          effect: 'deny',
          reason: policy.reason ?? `denied by policy ${policy.name}`,
          source: `${policy.name}@${policy.version}`,
          policy: deciding,
        };
      }
      allow ??= {
        effect: 'allow',
        reason: policy.reason ?? `allowed by policy ${policy.name}`,
        source: `${policy.name}@${policy.version}`,
        policy: deciding,
      };
    }

    // Null rather than deny: this evaluator has no opinion unless a policy matched, and an
    // opinion-free evaluator must not override the one that does have an opinion. Default deny is
    // applied by `combineDecisions`, once, so it cannot be forgotten here.
    return allow;
  },
};

function appliesTo(policy: PolicyRecord, request: AuthorizationRequest, holding: Holding | null): boolean {
  // Absent `principal` matches anyone; present, it decides by id or by pattern, ids winning.
  if (policy.principal && !selectorApplies(policy.principal, request.subjectId)) {
    return false;
  }
  // The permission the request is asking about, as the one string every side spells the same way.
  // `resolvedPermissions` already carries the role-derived union, so this needs no role lookup here.
  const asked = `${request.resource}:${request.action}`;
  if (!permissionApplies(policy, asked)) return false;
  // Which resource this governs, by exact id or by pattern. The query above already narrowed to
  // candidates for one or the other; this is the precise check, needed because `resource.pattern`
  // could not be excluded by the query itself.
  if (!selectorApplies(policy.resource, request.resource)) return false;

  // EVERY condition must hold. Any-of would mean adding a condition could WIDEN a policy, which is
  // the opposite of what somebody writing one down expects.
  return (policy.conditions ?? []).every((condition) => conditionHolds(condition, request.context, holding));
}

/** What roles and permissions this request's subject holds, resolved once for whichever conditions ask. */
type Holding = { roles: string[]; permissions: string[] };

/**
 * Identity-context conditions.
 *
 * Deliberately a small, closed set. An open expression language here would let a policy express a
 * business rule, and the line between identity context and business materiality is exactly what
 * must not blur.
 */
function conditionHolds(
  condition: PolicyCondition | undefined,
  context: Record<string, unknown>,
  holding: Holding | null,
): boolean {
  if (!condition) return true;

  if (condition.assuranceAtLeast) {
    const levels = ['aal1', 'aal2', 'aal3'];
    const held = levels.indexOf(String(context.assuranceLevel ?? 'aal1'));
    if (held < levels.indexOf(condition.assuranceAtLeast)) return false;
  }

  if (condition.ipInRange?.length) {
    const ip = String(context.ip ?? '');
    if (!condition.ipInRange.some((prefix) => ip.startsWith(prefix))) return false;
  }

  if (condition.timeOfDayUtc) {
    const hour = new Date().getUTCHours();
    const { from, to } = condition.timeOfDayUtc;
    const inWindow = from <= to ? hour >= from && hour < to : hour >= from || hour < to;
    if (!inWindow) return false;
  }

  if (condition.tenantIs && context.tenantId !== condition.tenantIs) return false;

  if (condition.attestationRequired && context.attestationState !== 'attested') return false;

  // At least one of the named roles. Membership, the way a group check is asked anywhere else: a
  // policy naming several roles means any of them satisfies it, not every one at once.
  if (condition.heldRole?.length) {
    const roles = holding?.roles ?? [];
    if (!condition.heldRole.some((role) => roles.includes(role))) return false;
  }

  // EVERY named permission, unlike the roles just above. This is the narrower, more exhaustive half
  // of the same requirement: naming several roles is "any one membership will do", naming several
  // permissions is "all of these specifically", because a permission is not a group somebody belongs
  // to, it is the exact thing that must already be held.
  if (condition.heldPermission?.length) {
    const permissions = holding?.permissions ?? [];
    if (!condition.heldPermission.every((permission) => permissions.includes(permission))) return false;
  }

  return true;
}

/**
 * Combines every evaluator. Deny wins, then allow, then default deny.
 *
 * The order of evaluators cannot change the outcome, which is the property that makes the rule
 * dependable: adding an evaluator can only ever make the result more restrictive.
 */
export async function combineDecisions(
  evaluators: PolicyEvaluator[],
  request: AuthorizationRequest,
): Promise<AuthorizationDecision> {
  const decisions = await Promise.all(evaluators.map((evaluator) => evaluator.evaluate(request)));

  const denial = decisions.find((decision) => decision?.effect === 'deny');
  if (denial) return denial;

  const permit = decisions.find((decision) => decision?.effect === 'allow');
  if (permit) return permit;

  return { effect: 'deny', reason: 'no evaluator allowed this request', source: 'default-deny' };
}
