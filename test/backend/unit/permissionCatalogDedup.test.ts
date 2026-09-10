// Two different resource servers can each declare a resource type of the same name (nothing stops
// "accounts" existing under two applications). The permission catalog is what the console renders
// as one flat, checkable list (e.g. the policy editor's permission picker), so a duplicate
// `resource:action` string there was a real React "duplicate key" crash, not just noise.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { RoleAdminService } from '../../../backend/src/modules/authorization/services/roleAdmin.service';
import { RESOURCE_COLLECTION } from '../../../backend/src/shared/models/collections';

function databaseHolding(resources: Array<Record<string, unknown>>): Db {
  return {
    collection(name: string) {
      if (name !== RESOURCE_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return {
        find: (filter: { realmId: string; status?: unknown }) => ({
          sort: () => ({
            toArray: async () => resources.filter((r) => r.realmId === filter.realmId),
          }),
        }),
      };
    },
  } as unknown as Db;
}

describe('the permission catalog never repeats a permission string', () => {
  it('keeps one entry when two different resource servers declare the same resource:action', async () => {
    const service = new RoleAdminService(databaseHolding([
      { realmId: 'r1', resourceId: 'srv-a', name: 'orders-api', kind: 'api', actions: [], catalogVersion: 1 },
      { realmId: 'r1', resourceId: 'srv-b', name: 'payments-api', kind: 'api', actions: [], catalogVersion: 1 },
      {
        realmId: 'r1', resourceId: 'res-a', parentResourceId: 'srv-a', name: 'accounts', kind: 'object',
        actions: ['view'], catalogVersion: 1,
      },
      {
        realmId: 'r1', resourceId: 'res-b', parentResourceId: 'srv-b', name: 'accounts', kind: 'object',
        actions: ['view'], catalogVersion: 1,
      },
    ]));

    const catalog = await service.catalog('r1');
    const permissions = catalog.map((entry) => entry.permission);
    expect(permissions).toEqual(['accounts:view']);
    expect(new Set(permissions).size).toBe(permissions.length);
  });

  it('still lists every distinct permission when nothing collides', async () => {
    const service = new RoleAdminService(databaseHolding([
      { realmId: 'r1', resourceId: 'srv-a', name: 'orders-api', kind: 'api', actions: [], catalogVersion: 1 },
      {
        realmId: 'r1', resourceId: 'res-a', parentResourceId: 'srv-a', name: 'orders', kind: 'object',
        actions: ['view', 'manage'], catalogVersion: 1,
      },
    ]));

    const catalog = await service.catalog('r1');
    expect(catalog.map((entry) => entry.permission)).toEqual(['orders:manage', 'orders:view']);
  });
});
