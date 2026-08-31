// v39 P8.2: deny wins, absolutely.
//
// Not "deny wins unless a more specific allow exists", not "the last statement wins". If anything
// denies, the answer is deny. Any other combination rule means a prohibition can be defeated by
// adding a permission somewhere else, and a prohibition that can be defeated is not one.
//
// The property that makes this dependable is order independence: adding an evaluator can only ever
// make a result MORE restrictive, so nobody has to reason about evaluation order to know what a
// policy does.
import { describe, it, expect } from 'vitest';
import { combineDecisions } from '../../../../giam/backend/src/modules/authorization/services/policyEvaluators';
import { matchesPattern } from '../../../../giam/backend/src/modules/authorization/models/policy.model';
import type { PolicyEvaluator, AuthorizationRequest } from '../../../../giam/backend/src/shared/ports';

const request: AuthorizationRequest = {
  realmId: 'r1',
  tenantId: 'default',
  subjectId: 's1',
  resource: 'accounts',
  action: 'view',
  context: {},
};

function evaluator(name: string, effect: 'allow' | 'deny' | null): PolicyEvaluator {
  return {
    name,
    async evaluate() {
      return effect ? { effect, reason: `${name} said ${effect}`, source: name } : null;
    },
  };
}

describe('v39 P8.2: the combination rule', () => {
  it('denies when anything denies, whatever else allows', async () => {
    const decision = await combineDecisions(
      [evaluator('a', 'allow'), evaluator('b', 'deny'), evaluator('c', 'allow')],
      request,
    );
    expect(decision.effect).toBe('deny');
  });

  it('reaches the same answer whatever the order', async () => {
    // The property that makes the rule dependable: nobody has to know the evaluation order to know
    // what a policy does.
    const forwards = await combineDecisions([evaluator('a', 'allow'), evaluator('b', 'deny')], request);
    const backwards = await combineDecisions([evaluator('b', 'deny'), evaluator('a', 'allow')], request);
    expect(forwards.effect).toBe(backwards.effect);
    expect(forwards.effect).toBe('deny');
  });

  it('allows only when something allows and nothing denies', async () => {
    const decision = await combineDecisions([evaluator('a', 'allow'), evaluator('b', null)], request);
    expect(decision.effect).toBe('allow');
  });

  it('denies by default when no evaluator has an opinion', async () => {
    // An absent decision is not an allow. This is the case that decides what happens to every
    // resource nobody wrote a rule for, which is most of them.
    const decision = await combineDecisions([evaluator('a', null), evaluator('b', null)], request);
    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('default-deny');
  });

  it('denies when there is no evaluator at all', async () => {
    const decision = await combineDecisions([], request);
    expect(decision.effect).toBe('deny');
  });

  it('carries a reason on every decision', async () => {
    // A decision a log cannot explain is not auditable, so there is no path that produces a bare
    // yes or no.
    for (const evaluators of [
      [evaluator('a', 'allow')],
      [evaluator('a', 'deny')],
      [],
    ]) {
      const decision = await combineDecisions(evaluators, request);
      expect(decision.reason.length).toBeGreaterThan(5);
    }
  });

  it('cannot be made more permissive by adding an evaluator', async () => {
    const before = await combineDecisions([evaluator('a', 'deny')], request);
    const after = await combineDecisions(
      [evaluator('a', 'deny'), evaluator('b', 'allow'), evaluator('c', 'allow')],
      request,
    );
    expect(before.effect).toBe('deny');
    expect(after.effect).toBe('deny');
  });
});

describe('v39 P8.2: policy patterns stay reviewable', () => {
  it('matches exactly, by prefix, or everything', () => {
    expect(matchesPattern('*', 'anything')).toBe(true);
    expect(matchesPattern('accounts', 'accounts')).toBe(true);
    expect(matchesPattern('accounts', 'accountsExtra')).toBe(false);
    expect(matchesPattern('account*', 'accountHolders')).toBe(true);
  });

  it('is not a regular expression', () => {
    // Deliberate. A pattern language that can express arbitrary matching produces policies nobody
    // can review, and review is the entire point of writing one down.
    expect(matchesPattern('.*', 'accounts')).toBe(false);
    expect(matchesPattern('accounts|cards', 'accounts')).toBe(false);
  });
});
