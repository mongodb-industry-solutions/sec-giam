import { Db } from 'mongodb';
import type { PolicyEvaluator, AuthorizationRequest, AuthorizationDecision } from '../../../shared/ports';
import { POLICY_COLLECTION } from '../../../shared/models/collections';
import { PolicyRecord, PolicyStatement, matchesPattern } from '../models/policy.model';
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
      .find({ realmId: request.realmId, tenantId: request.tenantId, enabled: true }, { projection: { _id: 0 } })
      .toArray();

    let allow: AuthorizationDecision | null = null;

    for (const policy of policies) {
      for (const statement of policy.statements) {
        if (!appliesTo(statement, request)) continue;
        if (statement.effect === 'deny') {
          // Returned immediately. Nothing later can overturn it, and evaluating on would only cost
          // time to reach the same answer.
          return {
            effect: 'deny',
            reason: statement.reason ?? `denied by policy ${policy.name}`,
            source: `${policy.name}@${policy.version}`,
          };
        }
        allow ??= {
          effect: 'allow',
          reason: statement.reason ?? `allowed by policy ${policy.name}`,
          source: `${policy.name}@${policy.version}`,
        };
      }
    }

    // Null rather than deny: this evaluator has no opinion unless a statement matched, and an
    // opinion-free evaluator must not override the one that does have an opinion.
    return allow;
  },
};

function appliesTo(statement: PolicyStatement, request: AuthorizationRequest): boolean {
  if (statement.principals?.length && !statement.principals.some((p) => matchesPattern(p, request.subjectId))) {
    return false;
  }
  if (statement.actions?.length && !statement.actions.some((a) => matchesPattern(a, request.action))) {
    return false;
  }
  if (statement.resources?.length && !statement.resources.some((r) => matchesPattern(r, request.resource))) {
    return false;
  }
  return conditionHolds(statement.condition, request.context);
}

/**
 * Identity-context conditions.
 *
 * Deliberately a small, closed set. An open expression language here would let a policy express a
 * business rule, and the line between identity context and business materiality is exactly what
 * must not blur.
 */
function conditionHolds(
  condition: PolicyStatement['condition'],
  context: Record<string, unknown>,
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
