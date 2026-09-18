// Two different resource servers can each declare a resource type of the same name (nothing stops
// "accounts" existing under two applications), and each ships its own guard over its own objects.
// The catalog lists ENFORCEMENT POINTS, so both are listed and each names the server that declares
// it: collapsing them to one entry reported the permission as belonging to an application that does
// not enforce it, and a resource server scoping the catalog to its own name saw nothing at all.
// Whoever renders it as one flat, checkable list collapses by string at the point of rendering,
// because a duplicated React key there was a real crash.
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

describe('the permission catalog lists a permission per resource server that enforces it', () => {
  it('lists both when two different resource servers declare the same resource:action', async () => {
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
    expect(catalog.map((entry) => `${entry.resourceServer}:${entry.permission}`))
      .toEqual(['orders-api:accounts:view', 'payments-api:accounts:view']);
    // Unique by the pair, which is what identifies an enforcement point.
    const pairs = catalog.map((entry) => `${entry.resourceServer}|${entry.permission}`);
    expect(new Set(pairs).size).toBe(pairs.length);
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
