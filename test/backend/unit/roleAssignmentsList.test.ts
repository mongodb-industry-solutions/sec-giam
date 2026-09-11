// `RoleAdminService.assignmentsFor`: who holds a role, now searchable and paged the same way every
// other list in the console already is, instead of reading everything unpaginated.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { RoleAdminService } from '../../../backend/src/modules/authorization/services/roleAdmin.service';
import { PRINCIPAL_COLLECTION } from '../../../backend/src/shared/models/collections';

const REALM_ID = 'r1';
const ROLE_ID = 'role-1';

function holder(subjectId: string, userName: string, grantedAt: string) {
  return {
    realmId: REALM_ID,
    subjectId,
    userName,
    roles: [{ roleId: ROLE_ID, grantedAt }],
  };
}

function fakeDb(holders: Array<Record<string, unknown>>): Db {
  return {
    collection(name: string) {
      if (name !== PRINCIPAL_COLLECTION) throw new Error(`unexpected collection ${name}`);
      return {
        find(filter: { realmId: string; 'roles.roleId': string; $or?: Array<Record<string, unknown>> }) {
          const found = holders.filter((doc) => {
            if (doc.realmId !== filter.realmId) return false;
            if (!(doc.roles as Array<{ roleId: string }>).some((r) => r.roleId === filter['roles.roleId'])) return false;
            if (filter.$or) {
              return filter.$or.some((clause) => Object.entries(clause).some(([field, cond]) => {
                const value = (doc as Record<string, unknown>)[field];
                const { $regex, $options } = cond as { $regex: string; $options?: string };
                return new RegExp($regex, $options).test(String(value ?? ''));
              }));
            }
            return true;
          });
          return { toArray: async () => found };
        },
      };
    },
  } as unknown as Db;
}

describe('RoleAdminService.assignmentsFor', () => {
  it('lists everyone holding the role, most recently granted first', async () => {
    const service = new RoleAdminService(fakeDb([
      holder('s1', 'ada', '2026-01-01T00:00:00.000Z'),
      holder('s2', 'grace', '2026-02-01T00:00:00.000Z'),
    ]));
    const { assignments, total } = await service.assignmentsFor(REALM_ID, ROLE_ID);
    expect(total).toBe(2);
    expect(assignments.map((a) => a.subjectId)).toEqual(['s2', 's1']);
  });

  it('narrows by subject id or user name', async () => {
    const service = new RoleAdminService(fakeDb([
      holder('s1', 'ada', '2026-01-01T00:00:00.000Z'),
      holder('s2', 'grace', '2026-02-01T00:00:00.000Z'),
    ]));
    const { assignments } = await service.assignmentsFor(REALM_ID, ROLE_ID, { q: 'grace' });
    expect(assignments.map((a) => a.subjectId)).toEqual(['s2']);
  });

  it('pages the result', async () => {
    const service = new RoleAdminService(fakeDb([
      holder('s1', 'ada', '2026-01-01T00:00:00.000Z'),
      holder('s2', 'grace', '2026-02-01T00:00:00.000Z'),
      holder('s3', 'linus', '2026-03-01T00:00:00.000Z'),
    ]));
    const { assignments, total } = await service.assignmentsFor(REALM_ID, ROLE_ID, { skip: 1, limit: 1 });
    expect(total).toBe(3);
    expect(assignments.map((a) => a.subjectId)).toEqual(['s2']);
  });
});
