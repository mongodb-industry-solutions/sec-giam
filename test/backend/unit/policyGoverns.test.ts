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
        const actual = at(doc, key);
        if (value && typeof value === 'object' && '$exists' in (value as Record<string, unknown>)) {
          return (actual !== undefined) === (value as { $exists: boolean }).$exists;
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
});
