// `ResourceAdminService.registerCatalog`: the one write the resource-server catalog has, shared by
// the admin-token route and the RBAC-gated console route. Idempotent by construction (deterministic
// uuidv5 ids), which is the property this suite exists to hold onto: replaying the same declaration
// must reach the same end state, never a second copy.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { ResourceAdminService } from '../../../backend/src/modules/authorization/services/resourceAdmin.service';
import { RESOURCE_COLLECTION, AUDIT_COLLECTION } from '../../../backend/src/shared/models/collections';

/** A minimal, STATEFUL fake: real upserts against an in-memory map, keyed by `resourceId`. */
function fakeDb() {
  const store = new Map<string, Record<string, unknown>>();
  const audit: Array<Record<string, unknown>> = [];
  const db = {
    collection(name: string) {
      if (name === AUDIT_COLLECTION) {
        return { insertOne: async (doc: Record<string, unknown>) => { audit.push(doc); } };
      }
      if (name !== RESOURCE_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return {
        findOne: async (filter: { resourceId: string }) => store.get(filter.resourceId) ?? null,
        updateOne: async (filter: { resourceId: string }, update: { $set: Record<string, unknown> }) => {
          store.set(filter.resourceId, { ...store.get(filter.resourceId), ...update.$set });
        },
        insertOne: async (doc: Record<string, unknown>) => { store.set(doc.resourceId as string, doc); },
        find: (filter: { realmId: string; parentResourceId?: string }) => ({
          toArray: async () => [...store.values()].filter((doc) => doc.realmId === filter.realmId && doc.parentResourceId === filter.parentResourceId),
        }),
      };
    },
  } as unknown as Db;
  return { db, store, audit };
}

const REALM_ID = 'r1';
const TENANT_ID = 'default';

describe('ResourceAdminService.registerCatalog', () => {
  it('registers a new server and its declared resource types', async () => {
    const { db } = fakeDb();
    const service = new ResourceAdminService(db);
    const outcome = await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }, { resource: 'orders', action: 'manage' }],
    });
    expect(outcome.registered).toBe(2);
    expect(outcome.deprecated).toBe(0);
  });

  it('replaying the identical declaration reaches the same state, not a second copy', async () => {
    const { db, store } = fakeDb();
    const service = new ResourceAdminService(db);
    const declaration = {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }, { resource: 'orders', action: 'manage' }],
    };

    const first = await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', declaration);
    const sizeAfterFirst = store.size;
    const second = await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', declaration);

    expect(second.resourceId).toBe(first.resourceId);
    expect(store.size).toBe(sizeAfterFirst);
    // The action set did not change, so the child's own catalogVersion must not have bumped either.
    const child = [...store.values()].find((doc) => doc.name === 'orders' && doc.kind === 'object');
    expect(child?.catalogVersion).toBe(1);
  });

  it('withdraws a resource type no longer declared, rather than deleting it', async () => {
    const { db, store } = fakeDb();
    const service = new ResourceAdminService(db);
    await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }, { resource: 'invoices', action: 'view' }],
    });
    await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }],
    });

    const invoices = [...store.values()].find((doc) => doc.name === 'invoices');
    expect(invoices?.status).toBe('withdrawn');
    // Still present, not removed: a role may already grant something over it.
    expect(invoices).toBeDefined();
  });

  it('bumps the child catalogVersion only when its declared action set actually changes', async () => {
    const { db, store } = fakeDb();
    const service = new ResourceAdminService(db);
    await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }],
    });
    await service.registerCatalog(REALM_ID, TENANT_ID, 'orders-api', {
      audience: 'orders-api',
      permissions: [{ resource: 'orders', action: 'view' }, { resource: 'orders', action: 'archive' }],
    });

    const child = [...store.values()].find((doc) => doc.name === 'orders' && doc.kind === 'object');
    expect(child?.catalogVersion).toBe(2);
    expect(child?.actions).toEqual(['archive', 'view']);
  });
});
