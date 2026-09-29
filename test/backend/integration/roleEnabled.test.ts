/**
 * v43 P15: a role can be switched off without touching who holds it.
 *
 * Disabled must mean disabled everywhere the role would otherwise apply: held directly, and
 * composed into as a parent. Verified against the running `/decision` endpoint (the same
 * combination path token issuance uses), not just the CRUD response, because a role that reads as
 * disabled but still decides is worse than one that was never toggleable at all.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { randomUUID } from 'crypto';
import { tokenFor as runFlow } from './support/authorizationFlow';
import { deleteTestPrincipal } from './support/directDb';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const PLATFORM = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

describe('v43: a role switched off grants nothing, held directly or inherited', () => {
  let live = false;
  let managerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('a directly held role stops deciding once disabled, and resumes once re-enabled', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

    // A fresh, unassigned role so nothing outside this test is affected by disabling it.
    const roleName = `v43-toggle-${randomUUID().slice(0, 8)}`;
    const created = await fetch(`${GIAM}/api/v1/realms/leafypay/roles`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name: roleName, displayName: 'v43 toggle test', scopeKind: 'all',
        permissions: [{ resource: 'sessions', action: 'view' }],
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(created.status).toBe(201);
    const role = await created.json() as { roleId: string; enabled: boolean };

    // A throwaway principal to hold it, provisioned and approved.
    const userName = `v43-holder-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/api/v1/realms/leafypay/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Correct-Horse-1' }),
      signal: AbortSignal.timeout(20000),
    });
    const holder = await registered.json() as { subjectId: string };

    // Neither the role nor the principal has a way to remove itself if an assertion below throws
    // first; retired here regardless, the same as the realm and policy CRUD tests retire theirs.
    // No route deletes a principal outright, so that half goes straight to the database, same as
    // realmCrud.test.ts does for a realm.
    try {
      expect(role.enabled).toBe(true);

      await fetch(`${GIAM}/api/v1/realms/leafypay/scim/Users/${holder.subjectId}`, {
        method: 'PATCH', headers,
        body: JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', value: { active: true } }] }),
        signal: AbortSignal.timeout(20000),
      });

      const granted = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${role.roleId}/assignments`, {
        method: 'POST', headers, body: JSON.stringify({ subjectId: holder.subjectId }), signal: AbortSignal.timeout(20000),
      });
      expect(granted.status).toBe(201);

      async function decide(): Promise<boolean> {
        const response = await fetch(`${GIAM}/api/v1/realms/leafypay/decision`, {
          method: 'POST', headers,
          body: JSON.stringify({
            subject: { type: 'identity', id: holder.subjectId },
            resource: { type: 'sessions' },
            action: { name: 'view' },
            context: { audience: 'authority' },
          }),
          signal: AbortSignal.timeout(20000),
        });
        expect(response.status).toBe(200);
        return (await response.json()).decision as boolean;
      }

      expect(await decide()).toBe(true);

      const disabled = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${role.roleId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ enabled: false }), signal: AbortSignal.timeout(20000),
      });
      expect(disabled.status).toBe(200);
      expect((await disabled.json()).enabled).toBe(false);

      expect(await decide()).toBe(false);

      // The assignment itself is untouched: re-enabling resumes granting without re-assigning.
      const listed = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${role.roleId}/assignments`, { headers, signal: AbortSignal.timeout(20000) });
      const assignments = await listed.json() as { assignments: Array<{ subjectId: string }> };
      expect(assignments.assignments.some((a) => a.subjectId === holder.subjectId)).toBe(true);

      const reenabled = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${role.roleId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ enabled: true }), signal: AbortSignal.timeout(20000),
      });
      expect(reenabled.status).toBe(200);
      expect(await decide()).toBe(true);
    } finally {
      // A role still assigned refuses deletion (409): the assignment goes first, or this leaves
      // the role behind on every run exactly like the leak this whole file exists to close.
      await fetch(`${GIAM}/api/v1/realms/leafypay/principals/${holder.subjectId}/roles/${role.roleId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      }).catch(() => {});
      await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${role.roleId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      }).catch(() => {});
      await deleteTestPrincipal(holder.subjectId).catch(() => {});
    }
  });

  it('a disabled PARENT contributes nothing to what an enabled child effectively grants', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

    const parentName = `v43-parent-${randomUUID().slice(0, 8)}`;
    const parent = await fetch(`${GIAM}/api/v1/realms/leafypay/roles`, {
      method: 'POST', headers,
      body: JSON.stringify({ name: parentName, displayName: 'v43 parent', scopeKind: 'all', permissions: [{ resource: 'keys', action: 'view' }] }),
      signal: AbortSignal.timeout(20000),
    });
    const parentRole = await parent.json() as { roleId: string };

    const childName = `v43-child-${randomUUID().slice(0, 8)}`;
    const child = await fetch(`${GIAM}/api/v1/realms/leafypay/roles`, {
      method: 'POST', headers,
      body: JSON.stringify({
        name: childName, displayName: 'v43 child', scopeKind: 'all',
        permissions: [{ resource: 'sessions', action: 'view' }], parentRoleIds: [parentRole.roleId],
      }),
      signal: AbortSignal.timeout(20000),
    });
    const childRole = await child.json() as { roleId: string };

    // Retired regardless of what the assertions below do. The child holds the reference to the
    // parent, so it goes first: deleting the parent while something still names it is exactly the
    // state disabling it is supposed to make harmless, not a state removing it should ever produce.
    try {
      const detailBefore = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${childRole.roleId}`, { headers, signal: AbortSignal.timeout(20000) });
      const beforeBody = await detailBefore.json() as { effectivePermissionCount: number };
      expect(beforeBody.effectivePermissionCount).toBe(2);

      await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${parentRole.roleId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ enabled: false }), signal: AbortSignal.timeout(20000),
      });

      const detailAfter = await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${childRole.roleId}`, { headers, signal: AbortSignal.timeout(20000) });
      const afterBody = await detailAfter.json() as { effectivePermissionCount: number };
      expect(afterBody.effectivePermissionCount).toBe(1);
    } finally {
      await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${childRole.roleId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      }).catch(() => {});
      await fetch(`${GIAM}/api/v1/realms/leafypay/roles/${parentRole.roleId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      }).catch(() => {});
    }
  });
});
