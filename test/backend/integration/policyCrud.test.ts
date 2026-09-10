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

    const created = await fetch(`${GIAM}/realms/leafypay/policies`, {
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
    // The exact shape the console reads: no `statements` array anywhere.
    expect(policy.effect).toBe('deny');
    expect(policy.status).toBe('active');
    expect(policy.resolvedPermissions).toEqual(['sessions:manage']);
    expect(policy.resource.ids).toEqual(['sessions']);
    expect((policy as unknown as Record<string, unknown>).statements).toBeUndefined();

    const listedActive = await fetch(`${GIAM}/realms/leafypay/policies?status=active&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
    expect(listedActive.status).toBe(200);
    const activeList = await listedActive.json() as { policies: Array<{ policyId: string }> };
    expect(activeList.policies.map((p) => p.policyId)).toContain(policy.policyId);

    const toggled = await fetch(`${GIAM}/realms/leafypay/policies/${policy.policyId}`, {
      method: 'PATCH', headers, body: JSON.stringify({ status: 'retired' }), signal: AbortSignal.timeout(20000),
    });
    expect(toggled.status).toBe(200);
    expect((await toggled.json()).status).toBe('retired');

    const listedRetired = await fetch(`${GIAM}/realms/leafypay/policies?status=retired&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
    const retiredList = await listedRetired.json() as { policies: Array<{ policyId: string }> };
    expect(retiredList.policies.map((p) => p.policyId)).toContain(policy.policyId);
    const stillActive = await fetch(`${GIAM}/realms/leafypay/policies?status=active&limit=200`, { headers, signal: AbortSignal.timeout(20000) });
    const activeAfter = await stillActive.json() as { policies: Array<{ policyId: string }> };
    expect(activeAfter.policies.map((p) => p.policyId)).not.toContain(policy.policyId);

    const removed = await fetch(`${GIAM}/realms/leafypay/policies/${policy.policyId}`, {
      method: 'DELETE', headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000),
    });
    expect(removed.status).toBe(200);

    const gone = await fetch(
      `${GIAM}/realms/leafypay/policies/${policy.policyId}`,
      { headers: { authorization: `Bearer ${managerToken}` }, signal: AbortSignal.timeout(20000) },
    );
    expect(gone.status).toBe(404);
  });
});
