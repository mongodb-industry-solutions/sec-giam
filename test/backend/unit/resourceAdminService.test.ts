// The resource-server catalog read, exercised without a real database: given the parents and
// children a realm's own `resource` collection would hold, list() must join them correctly and
// carry a withdrawn one through rather than drop it.
import { describe, it, expect } from 'vitest';
import { ResourceAdminService } from '../../../backend/src/modules/authorization/services/resourceAdmin.service';
import type { ResourceRecord } from '../../../backend/src/modules/authorization/models/resource.model';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import type { Db } from 'mongodb';

const REALM_ID = 'realm-1';

function record(overrides: Partial<ResourceRecord>): ResourceRecord {
  return {
    realmId: REALM_ID,
    tenantId: 'default',
    resourceId: 'r-default',
    kind: 'object',
    name: 'default',
    actions: [],
    catalogVersion: 1,
    status: 'active',
    meta: newMeta('Resource'),
    ...overrides,
  };
}

/** A `resource` collection holding exactly the records handed to it. */
function dbOf(records: ResourceRecord[]): Db {
  function matches(candidate: ResourceRecord, filter: Record<string, unknown>): boolean {
    if (filter.kind && typeof filter.kind === 'object' && '$ne' in (filter.kind as object)) {
      if (candidate.kind === (filter.kind as { $ne: string }).$ne) return false;
    }
    if (filter.parentResourceId && typeof filter.parentResourceId === 'object'
      && '$in' in (filter.parentResourceId as object)) {
      const allowed = (filter.parentResourceId as { $in: string[] }).$in;
      if (!candidate.parentResourceId || !allowed.includes(candidate.parentResourceId)) return false;
    }
    if (filter.status && candidate.status !== filter.status) return false;
    if (filter.$or) {
      const clauses = filter.$or as Array<Record<string, { $regex: string; $options?: string }>>;
      const hit = clauses.some((clause) => Object.entries(clause).some(([field, cond]) => {
        const value = (candidate as unknown as Record<string, unknown>)[field];
        return new RegExp(cond.$regex, cond.$options).test(String(value ?? ''));
      }));
      if (!hit) return false;
    }
    return candidate.realmId === filter.realmId;
  }

  return {
    collection: () => ({
      find: (filter: Record<string, unknown>) => {
        const found = records.filter((candidate) => matches(candidate, filter));
        return {
          sort: () => ({
            toArray: async () => found,
            skip: (n: number) => ({ limit: (m: number) => ({ toArray: async () => found.slice(n, n + m) }) }),
          }),
        };
      },
      countDocuments: async (filter: Record<string, unknown>) => records.filter((candidate) => matches(candidate, filter)).length,
    }),
  } as unknown as Db;
}

describe('ResourceAdminService.list', () => {
  it('returns nothing for a realm with no registered resource server', async () => {
    expect(await new ResourceAdminService(dbOf([])).list(REALM_ID)).toEqual({ resourceServers: [], total: 0 });
  });

  it('joins a server to its own children, and excludes object-kind records from the top level', async () => {
    const server = record({
      resourceId: 'srv-1', kind: 'api', name: 'orders-api', audience: 'orders-api', catalogVersion: 2,
    });
    const child = record({
      resourceId: 'res-1', kind: 'object', name: 'orders', parentResourceId: 'srv-1',
      actions: ['view', 'manage'], catalogVersion: 1,
    });
    const { resourceServers, total } = await new ResourceAdminService(dbOf([server, child])).list(REALM_ID);

    expect(total).toBe(1);
    expect(resourceServers).toHaveLength(1);
    expect(resourceServers[0]).toMatchObject({ resourceId: 'srv-1', name: 'orders-api', audience: 'orders-api' });
    expect(resourceServers[0].resources).toEqual([
      { resourceId: 'res-1', name: 'orders', actions: ['view', 'manage'], status: 'active', catalogVersion: 1 },
    ]);
  });

  it('keeps a withdrawn server and a withdrawn resource, status intact', async () => {
    const server = record({ resourceId: 'srv-1', kind: 'api', name: 'old-api', status: 'withdrawn' });
    const child = record({
      resourceId: 'res-1', kind: 'object', name: 'legacy', parentResourceId: 'srv-1', status: 'withdrawn',
    });
    const { resourceServers } = await new ResourceAdminService(dbOf([server, child])).list(REALM_ID);

    expect(resourceServers[0].status).toBe('withdrawn');
    expect(resourceServers[0].resources[0].status).toBe('withdrawn');
  });

  it('never crosses realms: a server from another realm is invisible', async () => {
    const own = record({ resourceId: 'srv-1', kind: 'api', name: 'mine' });
    const other = record({ resourceId: 'srv-2', kind: 'api', name: 'theirs', realmId: 'realm-2' });
    const { resourceServers } = await new ResourceAdminService(dbOf([own, other])).list(REALM_ID);

    expect(resourceServers.map((server) => server.name)).toEqual(['mine']);
  });

  it('narrows by name or audience, case-insensitively', async () => {
    const orders = record({ resourceId: 'srv-1', kind: 'api', name: 'orders-api', audience: 'orders' });
    const payments = record({ resourceId: 'srv-2', kind: 'api', name: 'payments-api', audience: 'payments' });
    const { resourceServers } = await new ResourceAdminService(dbOf([orders, payments])).list(REALM_ID, { q: 'PAY' });

    expect(resourceServers.map((server) => server.name)).toEqual(['payments-api']);
  });

  it('pages the top-level servers', async () => {
    const servers = ['a', 'b', 'c'].map((name, index) => record({ resourceId: `srv-${index}`, kind: 'api', name }));
    const { resourceServers, total } = await new ResourceAdminService(dbOf(servers)).list(REALM_ID, { skip: 1, limit: 1 });

    expect(total).toBe(3);
    expect(resourceServers.map((server) => server.name)).toEqual(['b']);
  });
});
