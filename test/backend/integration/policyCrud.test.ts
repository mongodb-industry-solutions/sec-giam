/**
 * v43 P6: the policy detail page was crashing on `detail.statements` because the console was still
 * built for the pre-v40 nested-statements model while the backend has been the flat single-rule
 * model since v40. This exercises the real contract the rewritten console pages now assume, end to
 * end, against the running backend: create, read, list with the new `status` filter, toggle status,
 * update, and remove.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { randomUUID } from 'crypto';
import { tokenFor as runFlow } from './support/authorizationFlow';

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

describe('v43: policy CRUD matches the flat model the console now assumes', () => {
  let live = false;
  let managerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('creates, reads, filters by status, toggles, updates and removes', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const name = `v43-crud-${randomUUID().slice(0, 8)}`;

    const created = await fetch(`${GIAM}/api/v1/realms/leafypay/policies`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name,
        effect: 'deny',
        resource: { ids: ['sessions'] },
        permission: { ids: ['sessions:manage'] },
        reason: 'v43 CRUD test',
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(created.status).toBe(201);
    const policy = await created.json() as {
      policyId: string; effect: string; status: string; resolvedPermissions: string[]; resource: { ids: string[] };
    };

    // Removed here regardless of what the assertions below do: an earlier one failing must not
    // leave this behind for the same reason the realm and role CRUD tests retire what they made.
    try {
      // The exact shape the console reads: no `statements` array anywhere.
      expect(policy.effect).toBe('deny');
      expect(policy.status).toBe('active');
      expect(policy.resolvedPermissions).toEqual(['sessions:manage']);
      expect(policy.resource.ids).toEqual(['sessions']);
      expect((policy as unknown as Record<string, unknown>).statements).toBeUndefined();

      const listedActive = await fetch(`${GIAM}/api/v1/realms/leafypay/policies?status=active&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
      expect(listedActive.status).toBe(200);
      const activeList = await listedActive.json() as { policies: Array<{ policyId: string }> };
      expect(activeList.policies.map((p) => p.policyId)).toContain(policy.policyId);

      const toggled = await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ status: 'retired' }), signal: AbortSignal.timeout(20000),
      });
      expect(toggled.status).toBe(200);
      expect((await toggled.json()).status).toBe('retired');

      const listedRetired = await fetch(`${GIAM}/api/v1/realms/leafypay/policies?status=retired&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
      const retiredList = await listedRetired.json() as { policies: Array<{ policyId: string }> };
      expect(retiredList.policies.map((p) => p.policyId)).toContain(policy.policyId);
      const stillActive = await fetch(`${GIAM}/api/v1/realms/leafypay/policies?status=active&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
      const activeAfter = await stillActive.json() as { policies: Array<{ policyId: string }> };
      expect(activeAfter.policies.map((p) => p.policyId)).not.toContain(policy.policyId);

      const removed = await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      });
      expect(removed.status).toBe(200);

      const gone = await fetch(
        `${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`,
        { headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000) },
      );
      expect(gone.status).toBe(404);
    } finally {
      // Best-effort and idempotent: the assertions above already delete it on the happy path, so
      // this is only load-bearing when one of them threw first.
      await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
      }).catch(() => {});
    }
  });

  /**
   * `governs` takes several names, which is what a resource SERVER's own page needs.
   *
   * A policy names the resource TYPES a server declares (`roles`, `sessions`), never the server, so
   * asking with the server's own name matched nothing and its page reported no policies at all
   * while several governed it. Asserting the comma form here because the single-name form kept
   * working throughout: the bug was only ever visible one level up.
   */
  it('matches a policy governing ANY of several names, and none for a server name', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}` };
    const ask = async (governs: string) => {
      const response = await fetch(
        `${GIAM}/api/v1/realms/leafypay/policies?governs=${encodeURIComponent(governs)}&limit=50`,
        { headers, signal: AbortSignal.timeout(20000) },
      );
      expect(response.status).toBe(200);
      return (await response.json()) as { total: number; policies: Array<{ name: string }> };
    };

    // The seeded catalog puts `roles` and `sessions` under the authority server, each governed.
    const byType = await ask('roles');
    expect(byType.total).toBeGreaterThan(0);

    const byTypes = await ask('roles,sessions');
    expect(byTypes.total).toBeGreaterThanOrEqual(byType.total);
    // Union, not intersection: a policy governing either name belongs in the answer.
    expect(byTypes.policies.map((policy) => policy.name)).toEqual(
      expect.arrayContaining(byType.policies.map((policy) => policy.name)),
    );

    // The control, and the reason the comma form exists: nothing names the server itself.
    expect((await ask('authority')).total).toBe(0);

    // Blank entries are ignored rather than matching everything.
    expect((await ask('roles,,')).total).toBe(byType.total);
  });

  /**
   * A PATCH that leaves an optional selector empty, which is what the console sends most of the time.
   *
   * `ids` carries `minItems: 1`, so `{ ids: [] }` is refused with
   * `/role/ids must NOT have fewer than 1 items`, while `{}` is accepted and states that the
   * selector names nothing. The console built the obvious thing and every save of a policy with no
   * role failed; the button stayed lit and the screen looked as though the click had missed.
   */
  it('accepts an empty selector as {}, and refuses { ids: [] }', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const name = `v43-empty-selector-${randomUUID().slice(0, 8)}`;

    const created = await fetch(`${GIAM}/api/v1/realms/leafypay/policies`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        name,
        effect: 'allow',
        resource: { ids: ['sessions'] },
        permission: { ids: ['sessions:view'] },
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(created.status).toBe(201);
    const policy = await created.json() as { policyId: string };

    try {
      // What the screen sends when Role and Principal were never touched.
      const patched = await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({
          effect: 'allow',
          resource: { ids: ['sessions'] },
          permission: { ids: ['sessions:view'] },
          role: {},
          principal: {},
          conditions: [],
          reason: 'an empty selector names nothing',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(patched.status, await patched.text()).toBe(200);

      // The control: the shape that was being sent before, and the error it answered with.
      const refused = await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ resource: { ids: ['sessions'] }, role: { ids: [] } }),
        signal: AbortSignal.timeout(20000),
      });
      expect(refused.status).toBe(400);
      expect((await refused.text()).toLowerCase()).toContain('fewer than 1 items');
    } finally {
      await fetch(`${GIAM}/api/v1/realms/leafypay/policies/${policy.policyId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${managerToken}` },
        signal: AbortSignal.timeout(20000),
      }).catch(() => {});
    }
  });

});
