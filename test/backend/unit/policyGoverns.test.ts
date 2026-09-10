// `PolicyAdminService.list({ governs })`: what a resource's own screen asks to find out which
// policies actually govern it, by name or by pattern, without a round trip per policy.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { PolicyAdminService } from '../../../backend/src/modules/authorization/services/policyAdmin.service';
import { POLICY_COLLECTION } from '../../../backend/src/shared/models/collections';

/** Enough of a collection for `find().sort().toArray()`. Filtering is real: `$or` and equality only. */
function databaseHolding(documents: Array<Record<string, unknown>>): Db {
  return {
    collection(name: string) {
      if (name !== POLICY_COLLECTION) throw new Error(`unexpected collection ${name}`);
      // Dot notation resolves through nested objects, exactly as Mongo does, and a value found on an
      // ARRAY field matches when any element equals it: `resource.names` is an array, and `{
      // 'resource.names': 'reports' }` is asking "does this array contain reports", not "does the
      // whole array equal the string", which is what a naive `===` would otherwise test.
      const at = (doc: unknown, path: string): unknown => path.split('.').reduce(
        (value, key) => (value && typeof value === 'object' ? (value as Record<string, unknown>)[key] : undefined),
        doc,
      );
      const matches = (doc: Record<string, unknown>, filter: Record<string, unknown>): boolean => Object.entries(filter).every(([key, value]) => {
        if (key === '$or') {
          return (value as Array<Record<string, unknown>>).some((clause) => matches(doc, clause));
        }
        if (key === '$and') {
          return (value as Array<Record<string, unknown>>).every((clause) => matches(doc, clause));
        }
        const actual = at(doc, key);
        if (value && typeof value === 'object' && '$exists' in (value as Record<string, unknown>)) {
          return (actual !== undefined) === (value as { $exists: boolean }).$exists;
        }
        if (value && typeof value === 'object' && '$regex' in (value as Record<string, unknown>)) {
          const { $regex, $options } = value as { $regex: string; $options?: string };
          return new RegExp($regex, $options).test(String(actual ?? ''));
        }
        if (Array.isArray(actual)) return actual.includes(value);
        return actual === value;
      });
      return {
        find(filter: Record<string, unknown>) {
          const found = documents.filter((doc) => matches(doc, filter));
          return {
            sort: () => ({ toArray: async () => found, skip: () => ({ limit: () => ({ toArray: async () => found }) }) }),
          };
        },
        countDocuments: async (filter: Record<string, unknown>) => documents.filter((doc) => matches(doc, filter)).length,
      };
    },
  } as unknown as Db;
}

const NAMED = {
  realmId: 'r1', tenantId: 'default', policyId: 'p-named', name: 'named-policy', version: 1,
  status: 'active', effect: 'deny', permissions: ['reports:export'],
  resource: { names: ['reports'] }, conditions: [],
};

const PATTERNED = {
  realmId: 'r1', tenantId: 'default', policyId: 'p-pattern', name: 'patterned-policy', version: 1,
  status: 'active', effect: 'allow', permissions: ['*:export'],
  resource: { pattern: '^report' }, conditions: [],
};

const UNRELATED = {
  realmId: 'r1', tenantId: 'default', policyId: 'p-other', name: 'unrelated-policy', version: 1,
  status: 'active', effect: 'allow', permissions: ['sessions:view'],
  resource: { names: ['sessions'] }, conditions: [],
};

// The old glob sentinel for "matches everything", left over from before RE2 validation existed.
// Not something `validatePolicy` would accept today, but a document written before it did is
// exactly the case this guards: reading the list must not 500 because ONE candidate's pattern
// happens not to compile.
const BROKEN_PATTERN = {
  realmId: 'r1', tenantId: 'default', policyId: 'p-broken', name: 'broken-pattern-policy', version: 1,
  status: 'active', effect: 'deny', permissions: ['*'],
  resource: { pattern: '*' }, conditions: [],
};

describe('listing policies that govern one resource', () => {
  it('finds a policy naming the resource exactly', async () => {
    const service = new PolicyAdminService(databaseHolding([NAMED, UNRELATED]));
    const { policies, total } = await service.list('r1', { governs: 'reports' });
    expect(total).toBe(1);
    expect(policies.map((p) => p.policyId)).toEqual(['p-named']);
  });

  it('finds a policy whose pattern matches, even though the resource is never named', async () => {
    const service = new PolicyAdminService(databaseHolding([PATTERNED, UNRELATED]));
    const { policies } = await service.list('r1', { governs: 'reports' });
    expect(policies.map((p) => p.policyId)).toEqual(['p-pattern']);
  });

  it('excludes a policy that governs a different resource entirely', async () => {
    const service = new PolicyAdminService(databaseHolding([NAMED, PATTERNED, UNRELATED]));
    const { policies } = await service.list('r1', { governs: 'sessions' });
    expect(policies.map((p) => p.policyId)).toEqual(['p-other']);
  });

  it('carries the resource selector on the summary, not only the detail', async () => {
    const service = new PolicyAdminService(databaseHolding([NAMED]));
    const { policies } = await service.list('r1', { governs: 'reports' });
    expect(policies[0].resource).toEqual({ names: ['reports'] });
  });

  it('combines with a name search instead of the search silently losing to governs', async () => {
    // The regression this guards: `governs` and `q` both used to assign their own `$or` onto the
    // same filter object, so asking for both together silently dropped whichever assigned second.
    const service = new PolicyAdminService(databaseHolding([NAMED, PATTERNED]));
    const { policies } = await service.list('r1', { governs: 'reports', q: 'named' });
    expect(policies.map((p) => p.policyId)).toEqual(['p-named']);
  });

  it('combines with a status filter the same way', async () => {
    const service = new PolicyAdminService(databaseHolding([NAMED, { ...PATTERNED, policyId: 'p-retired', status: 'retired' }]));
    const { policies } = await service.list('r1', { governs: 'reports', status: 'retired' });
    expect(policies.map((p) => p.policyId)).toEqual(['p-retired']);
  });

  it('does not fail the whole read because one candidate\'s pattern does not compile', async () => {
    const service = new PolicyAdminService(databaseHolding([NAMED, BROKEN_PATTERN, UNRELATED]));
    await expect(service.list('r1', { governs: 'reports' })).resolves.not.toThrow();
    const { policies } = await service.list('r1', { governs: 'reports' });
    // The broken one is a candidate at the query level (it has SOME pattern), but `resourceApplies`
    // resolves it to "does not match" rather than crashing, so it is silently excluded here, same as
    // any other policy that genuinely does not govern this resource.
    expect(policies.map((p) => p.policyId)).toEqual(['p-named']);
  });
});
