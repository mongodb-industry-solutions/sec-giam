// A policy naming a `role` governs by what that role currently grants, resolved once and cached in
// `resolvedPermissions` rather than looked up on every decision (`policy.model.ts`'s own docstring:
// "never resolved live, mid-decision"). These are the two pieces that keep that cache honest: which
// roles are affected when ONE role's shape changes (parents included), and the actual resync that
// recomputes and re-saves every policy naming any of them.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { RoleAdminService } from '../../../backend/src/modules/authorization/services/roleAdmin.service';
import { PolicyAdminService } from '../../../backend/src/modules/authorization/services/policyAdmin.service';
import { ROLE_COLLECTION, POLICY_COLLECTION } from '../../../backend/src/shared/models/collections';

interface RoleDoc { roleId: string; name: string; permissions: string[]; parentRoleIds?: string[] }
interface PolicyDoc {
  realmId: string; policyId: string; permission?: { ids?: string[] }; role?: { ids?: string[]; pattern?: string };
  resolvedPermissions: string[]; version: number; meta: { created: string; lastModified: string; version: number };
}

function fakeDb(roles: RoleDoc[], policies: PolicyDoc[]): Db {
  return {
    collection(name: string) {
      if (name === ROLE_COLLECTION) {
        return { find: () => ({ toArray: async () => roles }) };
      }
      if (name === POLICY_COLLECTION) {
        return {
          find(filter: Record<string, unknown>) {
            const matches = (doc: PolicyDoc) => Object.entries(filter).every(([key, value]) => {
              if (key === 'role.ids' && value && typeof value === 'object' && '$in' in (value as object)) {
                const wanted = (value as { $in: string[] }).$in;
                return (doc.role?.ids ?? []).some((id) => wanted.includes(id));
              }
              if (key === 'role.pattern' && value && typeof value === 'object' && '$exists' in (value as object)) {
                return (doc.role?.pattern !== undefined) === (value as { $exists: boolean }).$exists;
              }
              if (key === 'realmId') return doc.realmId === value;
              return true;
            });
            return { toArray: async () => policies.filter(matches) };
          },
          updateOne: async (filter: { realmId: string; policyId: string }, update: { $set: Partial<PolicyDoc> }) => {
            const doc = policies.find((p) => p.realmId === filter.realmId && p.policyId === filter.policyId);
            if (doc) Object.assign(doc, update.$set);
            return { matchedCount: doc ? 1 : 0 };
          },
        };
      }
      throw new Error(`unexpected collection ${name}`);
    },
  } as unknown as Db;
}

describe('RoleAdminService.namesAffectedByChangeTo', () => {
  it('names the role itself plus every descendant, not only direct children', async () => {
    const roles: RoleDoc[] = [
      { roleId: 'r-parent', name: 'reader', permissions: ['sessions:view'] },
      { roleId: 'r-child', name: 'auditor', permissions: ['reports:export'], parentRoleIds: ['r-parent'] },
      { roleId: 'r-grand', name: 'senior-auditor', permissions: [], parentRoleIds: ['r-child'] },
      { roleId: 'r-other', name: 'unrelated', permissions: [] },
    ];
    const service = new RoleAdminService(fakeDb(roles, []));
    const affected = await service.namesAffectedByChangeTo('r1', 'r-parent');
    expect(affected.sort()).toEqual(['auditor', 'reader', 'senior-auditor'].sort());
  });
});

describe('PolicyAdminService.resyncRoleReferences', () => {
  it('recomputes resolvedPermissions and bumps the version when a named role actually changed', async () => {
    const roles: RoleDoc[] = [{ roleId: 'r-auditor', name: 'auditor', permissions: ['reports:view'] }];
    const policies: PolicyDoc[] = [{
      realmId: 'r1', policyId: 'p1',
      permission: { ids: ['reports:export'] }, role: { ids: ['auditor'] },
      // Stale: written before the role granted reports:view.
      resolvedPermissions: ['reports:export'],
      version: 1, meta: { created: 't0', lastModified: 't0', version: 1 },
    }];
    const service = new PolicyAdminService(fakeDb(roles, policies));
    const resynced = await service.resyncRoleReferences('r1', ['auditor']);
    expect(resynced).toBe(1);
    expect(policies[0].resolvedPermissions.sort()).toEqual(['reports:export', 'reports:view'].sort());
    expect(policies[0].version).toBe(2);
  });

  it('leaves a policy alone, version included, when the resolved set genuinely did not change', async () => {
    const roles: RoleDoc[] = [{ roleId: 'r-auditor', name: 'auditor', permissions: ['reports:view'] }];
    const policies: PolicyDoc[] = [{
      realmId: 'r1', policyId: 'p1',
      permission: {}, role: { ids: ['auditor'] },
      resolvedPermissions: ['reports:view'],
      version: 3, meta: { created: 't0', lastModified: 't0', version: 3 },
    }];
    const service = new PolicyAdminService(fakeDb(roles, policies));
    const resynced = await service.resyncRoleReferences('r1', ['auditor']);
    expect(resynced).toBe(0);
    expect(policies[0].version).toBe(3);
  });

  it('leaves a policy naming a role that no longer exists untouched, rather than throwing', async () => {
    const policies: PolicyDoc[] = [{
      realmId: 'r1', policyId: 'p1',
      permission: {}, role: { ids: ['ghost'] },
      resolvedPermissions: [],
      version: 1, meta: { created: 't0', lastModified: 't0', version: 1 },
    }];
    const service = new PolicyAdminService(fakeDb([], policies));
    await expect(service.resyncRoleReferences('r1', ['ghost'])).resolves.toBe(0);
    expect(policies[0].version).toBe(1);
  });

  it('does nothing when no role name is given', async () => {
    const service = new PolicyAdminService(fakeDb([], []));
    expect(await service.resyncRoleReferences('r1', [])).toBe(0);
  });
});
