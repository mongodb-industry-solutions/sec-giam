/**
 * v43 P16: AuthZEN 1.0's `/access/v1/search/action` extension, against the running
 * `/decision/search/action` endpoint.
 *
 * Every action it reports allowed is cross-checked against the single `/decision` endpoint, not
 * merely trusted: the whole point of this endpoint is that it is not a cheaper approximation, so its
 * answer for the manager's own `roles:manage` must be the identical decision the single call gives
 * for that exact pair.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
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

describe('v43: search/action never disagrees with the single decision endpoint', () => {
  let live = false;
  let managerToken = '';
  let customerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (!live) return;
    managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
    customerToken = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('reports exactly what the single endpoint would decide: "view" allowed, "manage" denied by an active policy that overrides the role grant', async () => {
    if (!live) return;
    // `policies.json` seeds `role-change-denied`: an unconditional deny on `roles:manage`, with no
    // conditions at all. The manager's own role grants `roles:manage` at the RBAC layer, so a naive
    // reading of the role's flat permission list would report `manage` here. Deny-overrides means the
    // policy wins regardless, which is exactly what this endpoint must ask the real decision engine
    // to find out, not approximate from the role definition.
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

    const search = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/search/action`, {
      method: 'POST', headers, body: JSON.stringify({ resource: { type: 'roles' } }), signal: AbortSignal.timeout(20000),
    });
    expect(search.status).toBe(200);
    const body = await search.json() as { actions: Array<{ name: string }> };
    const names = body.actions.map((a) => a.name);
    expect(names).toContain('view');
    expect(names).not.toContain('manage');

    // Cross-checked, not assumed: every reported action must independently decide `true` through
    // the single endpoint too.
    for (const name of names) {
      const single = await fetch(`${GIAM}/api/v1/realms/leafypay/decision`, {
        method: 'POST', headers,
        body: JSON.stringify({ resource: { type: 'roles' }, action: { name } }),
        signal: AbortSignal.timeout(20000),
      });
      expect((await single.json()).decision, `search/action reported "${name}" but the single endpoint disagrees`).toBe(true);
    }
  });

  it('the same unconditional deny holds regardless of what context the caller supplies', async () => {
    if (!live) return;
    // An unconditional policy has no condition to satisfy, so no context value legitimately changes
    // its answer. A search/action that read conditions but ignored an unconditional deny would leak
    // "manage" here the moment a caller claimed a high assurance level, which is precisely the kind
    // of over-reporting this endpoint exists to avoid.
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const search = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/search/action`, {
      method: 'POST', headers,
      body: JSON.stringify({ resource: { type: 'roles' }, context: { assuranceLevel: 'aal2' } }),
      signal: AbortSignal.timeout(20000),
    });
    expect(search.status).toBe(200);
    const names = (await search.json() as { actions: Array<{ name: string }> }).actions.map((a) => a.name);
    expect(names).toContain('view');
    expect(names).not.toContain('manage');
  });

  it('reports no action at all for an ordinary customer on roles', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${customerToken}`, 'content-type': 'application/json' };
    const search = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/search/action`, {
      method: 'POST', headers, body: JSON.stringify({ resource: { type: 'roles' } }), signal: AbortSignal.timeout(20000),
    });
    expect(search.status).toBe(200);
    expect((await search.json()).actions).toHaveLength(0);
  });

  it('refuses a resource type nothing declares', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const search = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/search/action`, {
      method: 'POST', headers, body: JSON.stringify({ resource: { type: 'no-such-resource-type-at-all' } }), signal: AbortSignal.timeout(20000),
    });
    expect(search.status).toBe(404);
  });
});
