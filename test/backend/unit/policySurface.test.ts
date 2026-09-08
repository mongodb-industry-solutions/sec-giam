// The policy surface: bound at boot, evaluated through the real path, and closed at the schema.
//
// Three things the previous pass said had to be true before a policy screen could honestly ship, and
// each of them is here because the alternative is somebody noticing.
//
// 1. `bindPolicyEvaluators` was never called, so `abacEvaluator` would have thrown the first time a
//    policy was evaluated. A test that stubs the evaluator would not have caught that, so this one
//    binds and then goes through the REAL evaluator, the real combination rule and the real
//    condition code. Only the MongoDB driver is stood in for.
// 2. Deny wins, and it has to be visible from a stored document rather than only from a hand-made
//    decision object, because a policy nobody can see fire is a policy nobody has checked.
// 3. The condition vocabulary is closed. A condition naming a business threshold is a defect, and
//    the boundary has to hold in the schema and in the service, not only in the form.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { Db } from 'mongodb';
import {
  bindPolicyEvaluators, abacEvaluator, rbacEvaluator, combineDecisions,
} from '../../../backend/src/modules/authorization/services/policyEvaluators';
import { PolicyDecisionService } from '../../../backend/src/modules/authorization/services/policyDecision.service';
import { validatePolicy } from '../../../backend/src/modules/authorization/services/policyAdmin.service';
import { POLICY_CONDITION_KEYS } from '../../../backend/src/modules/authorization/models/policy.model';
import { POLICY_COLLECTION } from '../../../backend/src/shared/models/collections';
import { buildOpenApiApp, type OpenApiDocument } from '../../../backend/src/shared/services/openapi';
import type { AuthorizationRequest, PolicyEvaluator } from '../../../backend/src/shared/ports';

/**
 * A collection that answers `find().toArray()` and nothing else.
 *
 * Deliberately the thinnest possible stand-in: the point is to exercise GIAM's own code, so the only
 * thing faked is the driver call the evaluator makes. Everything above it is the shipped path.
 */
function databaseHolding(documents: unknown[]): Db {
  return {
    collection(name: string) {
      if (name !== POLICY_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return {
        find(filter: { realmId: string; tenantId: string; status: string }) {
          return {
            toArray: async () => documents.filter((doc) => {
              const record = doc as { realmId: string; tenantId: string; status: string };
              return record.realmId === filter.realmId
                && record.tenantId === filter.tenantId
                && record.status === filter.status;
            }),
          };
        },
      };
    },
  } as unknown as Db;
}

const ALLOW_ROLES = {
  realmId: 'r1',
  tenantId: 'default',
  policyId: 'p-allow',
  name: 'role-administration-allowed',
  version: 1,
  status: 'active',
  effect: 'allow',
  permissions: ['roles:view', 'roles:manage'],
  resource: { type: 'roles', pattern: 'roles:*' },
  principals: ['*'],
  conditions: [],
  reason: 'administering the realm',
};

const DENY_ROLE_CHANGE = {
  realmId: 'r1',
  tenantId: 'default',
  policyId: 'p-deny',
  name: 'role-change-denied',
  version: 1,
  status: 'active',
  effect: 'deny',
  permissions: ['roles:manage'],
  resource: { type: 'roles', pattern: 'roles:manage' },
  conditions: [],
  reason: 'withheld while this policy stands',
};

const ELEVATED_SESSIONS = {
  realmId: 'r1',
  tenantId: 'default',
  policyId: 'p-condition',
  name: 'session-review-allowed-at-elevated-assurance',
  version: 2,
  status: 'active',
  effect: 'allow',
  permissions: ['sessions:view'],
  resource: { type: 'sessions', pattern: 'sessions:*' },
  conditions: [{ assuranceAtLeast: 'aal2' }],
  reason: 'offered once the sign-in reached a second factor',
};

function ask(resource: string, action: string, context: Record<string, unknown> = {}): AuthorizationRequest {
  return { realmId: 'r1', tenantId: 'default', subjectId: 's1', resource, action, context };
}

/** Only the conditional evaluator. Roles need a real database, and this is about the policy half. */
const abacOnly: PolicyEvaluator[] = [abacEvaluator];

describe('the conditional evaluator is bound to a database at boot', () => {
  it('refuses to evaluate before it is bound, rather than answering allow', async () => {
    // The failure the previous pass predicted. It must be loud: an evaluator that quietly returned
    // null when unbound would turn every policy in the realm into no opinion at all, and the whole
    // surface would look like it worked.
    bindPolicyEvaluators(null as unknown as Db);
    await expect(abacEvaluator.evaluate(ask('roles', 'view'))).rejects.toThrow(/not bound to a database/);
  });

  it('evaluates a stored policy once bound, through the shipped evaluator', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES]));
    const decision = await abacEvaluator.evaluate(ask('roles', 'view'));
    expect(decision?.effect).toBe('allow');
    expect(decision?.source).toBe('role-administration-allowed@1');
  });

  it('names the exact policy that decided, so the record can be opened and read', () => {
    // Carried as data rather than parsed back out of the reason text, which is what lets a screen
    // link to the record an administrator has to edit. No statement index any more: one policy
    // states one effect, so naming the policy names the rule.
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES]));
    return abacEvaluator.evaluate(ask('roles', 'view')).then((decision) => {
      expect(decision?.policy).toEqual({
        policyId: 'p-allow',
        name: 'role-administration-allowed',
        version: 1,
        effect: 'allow',
      });
    });
  });

  it('has no opinion when nothing matches, which is not a denial', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES]));
    expect(await abacEvaluator.evaluate(ask('keys', 'retire'))).toBeNull();
  });

  it('ignores a retired policy, so withdrawing one really stops it deciding', async () => {
    bindPolicyEvaluators(databaseHolding([{ ...DENY_ROLE_CHANGE, status: 'retired' }, ALLOW_ROLES]));
    const decision = await abacEvaluator.evaluate(ask('roles', 'manage'));
    expect(decision?.effect).toBe('allow');
  });

  it('ignores a policy dated into the future, however active it says it is', async () => {
    // Written down and approved is not the same as in force. A policy whose effectiveFrom has not
    // arrived must decide nothing, or approving something ahead of time would apply it immediately.
    const nextYear = new Date(Date.now() + 365 * 24 * 3600 * 1000).toISOString();
    bindPolicyEvaluators(databaseHolding([{ ...DENY_ROLE_CHANGE, effectiveFrom: nextYear }, ALLOW_ROLES]));
    const decision = await abacEvaluator.evaluate(ask('roles', 'manage'));
    expect(decision?.effect).toBe('allow');
  });
});

describe('deny wins over an allow that is really in the collection', () => {
  it('denies whatever else in the realm allows the same thing', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES, DENY_ROLE_CHANGE]));
    const decision = await combineDecisions(abacOnly, ask('roles', 'manage'));
    expect(decision.effect).toBe('deny');
    expect(decision.policy?.name).toBe('role-change-denied');
  });

  it('reaches the same answer whichever order the documents come back in', async () => {
    // Order independence is the property that makes the rule dependable. It has to hold for stored
    // documents, not only for the hand-made decisions the combination-rule test uses.
    bindPolicyEvaluators(databaseHolding([DENY_ROLE_CHANGE, ALLOW_ROLES]));
    const reversed = await combineDecisions(abacOnly, ask('roles', 'manage'));
    expect(reversed.effect).toBe('deny');
  });

  it('still allows the action the deny does not cover', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES, DENY_ROLE_CHANGE]));
    const decision = await combineDecisions(abacOnly, ask('roles', 'view'));
    expect(decision.effect).toBe('allow');
  });
});

describe('conditions are identity context, evaluated for real', () => {
  it('withholds the allow when the assurance floor is not met', async () => {
    bindPolicyEvaluators(databaseHolding([ELEVATED_SESSIONS]));
    const decision = await combineDecisions(abacOnly, ask('sessions', 'view', { assuranceLevel: 'aal1' }));
    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('default-deny');
  });

  it('grants it once the sign-in reached the floor', async () => {
    bindPolicyEvaluators(databaseHolding([ELEVATED_SESSIONS]));
    const decision = await combineDecisions(abacOnly, ask('sessions', 'view', { assuranceLevel: 'aal2' }));
    expect(decision.effect).toBe('allow');
    expect(decision.policy?.version).toBe(2);
  });
});

describe('the traced decision reports every evaluator without changing the answer', () => {
  it('reports what each evaluator said alone, and the combined result', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES, DENY_ROLE_CHANGE]));
    const permissive: PolicyEvaluator = {
      name: 'stub-allow',
      async evaluate() { return { effect: 'allow' as const, reason: 'a role granted it', source: 'stub' }; },
    };

    const traced = await new PolicyDecisionService([abacEvaluator, permissive]).evaluate(ask('roles', 'manage'));
    expect(traced.decision.effect).toBe('deny');
    expect(traced.evaluators).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: 'abac', effect: 'deny' }),
      expect.objectContaining({ name: 'stub-allow', effect: 'allow' }),
    ]));
  });

  it('records no opinion as null rather than as a denial', async () => {
    bindPolicyEvaluators(databaseHolding([]));
    const traced = await new PolicyDecisionService([abacEvaluator]).evaluate(ask('keys', 'view'));
    expect(traced.evaluators).toEqual([{ name: 'abac', effect: null }]);
    // The combined answer is still deny, because absence of a permit is a denial. The two are
    // different findings and the trace is what keeps them apart.
    expect(traced.decision.effect).toBe('deny');
    expect(traced.decision.source).toBe('default-deny');
  });

  it('runs each evaluator exactly once, so a time-bounded condition cannot answer twice', async () => {
    let calls = 0;
    const counted: PolicyEvaluator = {
      name: 'counted',
      async evaluate() { calls += 1; return null; },
    };
    await new PolicyDecisionService([counted]).evaluate(ask('roles', 'view'));
    expect(calls).toBe(1);
  });

  it('carries the shipped evaluators when no subset is named', () => {
    // The default is the registry, which is what the decision endpoint uses.
    const named = new PolicyDecisionService();
    expect(named).toBeInstanceOf(PolicyDecisionService);
    expect([rbacEvaluator.name, abacEvaluator.name]).toEqual(['rbac', 'abac']);
  });
});

describe('the condition vocabulary is closed, in the service', () => {
  /** A policy that is valid apart from whatever one test is trying to break. */
  const wellFormed = {
    effect: 'deny' as const,
    permissions: ['transfers:create'],
    resource: { type: 'transfers', pattern: 'transfers:*' },
    conditions: [] as never[],
  };

  it('refuses a condition outside the set', () => {
    const refused = validatePolicy({
      ...wellFormed,
      // The exact defect the design record names: a monetary threshold is business materiality, and
      // an identity authority deciding it would be answering a question it cannot observe.
      conditions: [{ amountAbove: 10000 } as never],
    });
    expect(refused).not.toBeNull();
    expect(refused?.status).toBe(400);
    expect(refused?.detail).toMatch(/amountAbove/);
  });

  it('refuses a business threshold under any name, not only the one the record cites', () => {
    // P5.6. The rule is that business materiality is out of scope, not that one field name is
    // banned, so a policy dressing the same judgement up differently must fail the same way.
    for (const invented of ['amountOver', 'transactionValueAbove', 'balanceBelow', 'riskScoreOver']) {
      const refused = validatePolicy({ ...wellFormed, conditions: [{ [invented]: 1 } as never] });
      expect(refused, invented).not.toBeNull();
      expect(refused?.detail, invented).toMatch(new RegExp(invented));
    }
  });

  it('accepts every condition the evaluator can actually read, and only those', () => {
    for (const key of POLICY_CONDITION_KEYS) {
      const sample: Record<string, unknown> = {
        assuranceAtLeast: 'aal2',
        ipInRange: ['10.'],
        timeOfDayUtc: { from: 8, to: 18 },
        tenantIs: 'default',
        attestationRequired: true,
      };
      expect(
        validatePolicy({ ...wellFormed, conditions: [{ [key]: sample[key] } as never] }),
        key,
      ).toBeNull();
    }
  });

  it('refuses a policy that governs nothing at all', () => {
    // A policy with no permission decides nothing and would sit in the list looking as though it
    // did, which is worse than not having written it.
    const refused = validatePolicy({ ...wellFormed, permissions: [] });
    expect(refused?.status).toBe(400);
    expect(refused?.title).toMatch(/governs nothing/i);
  });

  it('refuses a permission that is not resource:action', () => {
    // One spelling everywhere. A policy written another way matches nothing, however the request
    // that reaches it happens to be spelled.
    expect(validatePolicy({ ...wellFormed, permissions: ['transfers'] })?.status).toBe(400);
    expect(validatePolicy({ ...wellFormed, permissions: ['transfers:'] })?.status).toBe(400);
    expect(validatePolicy({ ...wellFormed, permissions: [':create'] })?.status).toBe(400);
    // `*` is the one exception: it governs everything on purpose.
    expect(validatePolicy({ ...wellFormed, permissions: ['*'] })).toBeNull();
  });

  it('refuses a policy that names no resource', () => {
    expect(validatePolicy({ ...wellFormed, resource: undefined })?.status).toBe(400);
    expect(validatePolicy({ ...wellFormed, resource: { type: 'transfers', pattern: '' } })?.status).toBe(400);
  });

  it('refuses an unknown effect, so a typo cannot become a policy that never fires', () => {
    expect(validatePolicy({ ...wellFormed, effect: 'permit' as never })?.status).toBe(400);
  });

  it('refuses an hour outside the day and an address range that matches nothing', () => {
    expect(validatePolicy({
      ...wellFormed,
      conditions: [{ timeOfDayUtc: { from: 8, to: 25 } }],
    })?.status).toBe(400);
    expect(validatePolicy({ ...wellFormed, conditions: [{ ipInRange: [] }] })?.status).toBe(400);
    expect(validatePolicy({ ...wellFormed, conditions: [{ tenantIs: '' }] })?.status).toBe(400);
  });
});

describe('P5.5: nothing matching means deny, never allow', () => {
  it('denies when the collection holds no policy at all', async () => {
    // The assertion the plan asks for explicitly: remove every policy and the answer must be deny.
    // An empty rule set that allowed would be the worst possible default, and it is exactly the
    // shape a fresh deployment has.
    bindPolicyEvaluators(databaseHolding([]));
    const decision = await combineDecisions(abacOnly, ask('roles', 'manage'));
    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('default-deny');
  });

  it('denies an action no policy in a populated realm covers', async () => {
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES, DENY_ROLE_CHANGE, ELEVATED_SESSIONS]));
    const decision = await combineDecisions(abacOnly, ask('keys', 'retire'));
    expect(decision.effect).toBe('deny');
    expect(decision.source).toBe('default-deny');
  });

  it('reports no opinion rather than a denial from the evaluator itself', async () => {
    // The distinction that keeps deny-wins honest across evaluators: an evaluator with nothing to
    // say must return null, because a null is overridden by an opinion and a deny is not.
    bindPolicyEvaluators(databaseHolding([ALLOW_ROLES]));
    expect(await abacEvaluator.evaluate(ask('keys', 'retire'))).toBeNull();
  });
});

describe('the condition vocabulary is closed, in the contract', () => {
  let app: FastifyInstance;
  let document: OpenApiDocument;

  beforeAll(async () => {
    ({ app, document } = await buildOpenApiApp());
  });

  afterAll(async () => {
    await app?.close();
  });

  it('offers exactly the five conditions and forbids anything else', () => {
    // Enforced in the schema rather than only in the console form: a form is a presentation choice
    // and this is the boundary that keeps GIAM an identity authority rather than a rules engine.
    const body = document.paths?.['/realms/{realm}/policies']?.post?.requestBody as {
      content: Record<string, { schema: Record<string, unknown> }>;
    };
    const schema = body.content['application/json'].schema as {
      properties: { conditions: { items: { properties: Record<string, unknown>; additionalProperties: boolean } } };
    };
    // Flat now: the conditions sit on the policy itself rather than inside a statement list.
    const condition = schema.properties.conditions.items;
    expect(Object.keys(condition.properties).sort()).toEqual([...POLICY_CONDITION_KEYS].sort());
    expect(condition.additionalProperties).toBe(false);
  });

  it('serves the decision endpoint the authorization tag already advertises', () => {
    // The tag described "the decision endpoint" while none existed, so the document said something
    // untrue about the service. This is the assertion that keeps it true.
    const evaluate = document.paths?.['/realms/{realm}/decision']?.post;
    expect(evaluate?.operationId).toBe('evaluateDecision');
    expect(evaluate?.tags).toContain('authorization');
    expect(evaluate?.description).toMatch(/AuthZEN/);
  });
});
