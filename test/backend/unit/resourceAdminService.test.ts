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
  return {
    collection: () => ({
      find: (filter: Record<string, unknown>) => ({
        sort: () => ({
          toArray: async () => records.filter((candidate) => {
            if (filter.kind && typeof filter.kind === 'object' && '$ne' in (filter.kind as object)) {
              if (candidate.kind === (filter.kind as { $ne: string }).$ne) return false;
            }
            if (filter.parentResourceId && typeof filter.parentResourceId === 'object'
              && '$in' in (filter.parentResourceId as object)) {
              const allowed = (filter.parentResourceId as { $in: string[] }).$in;
              if (!candidate.parentResourceId || !allowed.includes(candidate.parentResourceId)) return false;
            }
            return candidate.realmId === filter.realmId;
          }),
        }),
      }),
    }),
  } as unknown as Db;
}

describe('ResourceAdminService.list', () => {
  it('returns nothing for a realm with no registered resource server', async () => {
    expect(await new ResourceAdminService(dbOf([])).list(REALM_ID)).toEqual([]);
  });

  it('joins a server to its own children, and excludes object-kind records from the top level', async () => {
    const server = record({
      resourceId: 'srv-1', kind: 'api', name: 'orders-api', audience: 'orders-api', catalogVersion: 2,
    });
    const child = record({
      resourceId: 'res-1', kind: 'object', name: 'orders', parentResourceId: 'srv-1',
      actions: ['view', 'manage'], catalogVersion: 1,
    });
    const list = await new ResourceAdminService(dbOf([server, child])).list(REALM_ID);

    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ resourceId: 'srv-1', name: 'orders-api', audience: 'orders-api' });
    expect(list[0].resources).toEqual([
      { resourceId: 'res-1', name: 'orders', actions: ['view', 'manage'], status: 'active', catalogVersion: 1 },
    ]);
  });

  it('keeps a withdrawn server and a withdrawn resource, status intact', async () => {
    const server = record({ resourceId: 'srv-1', kind: 'api', name: 'old-api', status: 'withdrawn' });
    const child = record({
      resourceId: 'res-1', kind: 'object', name: 'legacy', parentResourceId: 'srv-1', status: 'withdrawn',
    });
    const list = await new ResourceAdminService(dbOf([server, child])).list(REALM_ID);

    expect(list[0].status).toBe('withdrawn');
    expect(list[0].resources[0].status).toBe('withdrawn');
  });

  it('never crosses realms: a server from another realm is invisible', async () => {
    const own = record({ resourceId: 'srv-1', kind: 'api', name: 'mine' });
    const other = record({ resourceId: 'srv-2', kind: 'api', name: 'theirs', realmId: 'realm-2' });
    const list = await new ResourceAdminService(dbOf([own, other])).list(REALM_ID);

    expect(list.map((server) => server.name)).toEqual(['mine']);
  });
});
