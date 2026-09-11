// `ResourceAdminService.matching`: the reverse of `?governs=` — given a policy's own resource
// selector, which of the realm's registered resources does it actually cover. What the policy
// detail page's own "resources this policy governs" list is built from.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { ResourceAdminService } from '../../../backend/src/modules/authorization/services/resourceAdmin.service';
import { RESOURCE_COLLECTION } from '../../../backend/src/shared/models/collections';

const REALM_ID = 'r1';

function dbOf(resources: Array<Record<string, unknown>>): Db {
  return {
    collection(name: string) {
      if (name !== RESOURCE_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return {
        find: (filter: { realmId: string; kind: string }) => ({
          sort: () => ({
            toArray: async () => resources.filter((r) => r.realmId === filter.realmId && r.kind === filter.kind),
          }),
        }),
      };
    },
  } as unknown as Db;
}

describe('ResourceAdminService.matching', () => {
  it('resolves a names-based selector to exactly the resources it names', async () => {
    const service = new ResourceAdminService(dbOf([
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-1', name: 'reports', status: 'active' },
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-2', name: 'invoices', status: 'active' },
    ]));
    const matches = await service.matching(REALM_ID, { ids: ['reports'] });
    expect(matches).toEqual([{ resourceId: 'res-1', name: 'reports', status: 'active' }]);
  });

  it('resolves a pattern-based selector against every registered resource', async () => {
    const service = new ResourceAdminService(dbOf([
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-1', name: 'reports', status: 'active' },
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-2', name: 'report-archives', status: 'active' },
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-3', name: 'invoices', status: 'active' },
    ]));
    const matches = await service.matching(REALM_ID, { pattern: '^report' });
    expect(matches.map((m) => m.name).sort()).toEqual(['report-archives', 'reports']);
  });

  it('never crosses realms, and excludes top-level servers from the match set', async () => {
    const service = new ResourceAdminService(dbOf([
      { realmId: REALM_ID, kind: 'object', resourceId: 'res-1', name: 'reports', status: 'active' },
      { realmId: 'r2', kind: 'object', resourceId: 'res-2', name: 'reports', status: 'active' },
      { realmId: REALM_ID, kind: 'api', resourceId: 'srv-1', name: 'reports', status: 'active' },
    ]));
    const matches = await service.matching(REALM_ID, { ids: ['reports'] });
    expect(matches.map((m) => m.resourceId)).toEqual(['res-1']);
  });
});
