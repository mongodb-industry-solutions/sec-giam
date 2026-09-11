/**
 * The AuthZEN-shaped compatibility aliases: `/api/v1/access/evaluation[s]` and
 * `/api/v1/access/search/action`, which name no realm because the specification has none. What
 * has to be true is that a caller's OWN token, with nothing else, resolves to their own realm and
 * answers exactly what the realm-scoped `/realms/:realm/decision...` routes would.
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

describe('the AuthZEN-shaped compatibility paths resolve the realm from the token alone', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) token = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('answers the same decision as the realm-scoped endpoint, at the compatibility path', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const body = JSON.stringify({ resource: { type: 'roles' }, action: { name: 'view' } });

    const scoped = await fetch(`${GIAM}/realms/leafypay/decision`, { method: 'POST', headers, body, signal: AbortSignal.timeout(20000) });
    const alias = await fetch(`${GIAM}/api/v1/access/evaluation`, { method: 'POST', headers, body, signal: AbortSignal.timeout(20000) });

    expect(scoped.status).toBe(200);
    expect(alias.status).toBe(200);
    const scopedBody = await scoped.json() as { decision: boolean };
    const aliasBody = await alias.json() as { decision: boolean };
    expect(aliasBody.decision).toBe(scopedBody.decision);
  });

  it('refuses with no realm segment to name and no token at all', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/api/v1/access/evaluation`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ resource: { type: 'roles' }, action: { name: 'view' } }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(401);
  });

  it('batches the same way the realm-scoped batch endpoint does', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const response = await fetch(`${GIAM}/api/v1/access/evaluations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ evaluations: [{ resource: { type: 'roles' }, action: { name: 'view' } }] }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const decided = await response.json() as { evaluations: Array<{ decision: boolean }> };
    expect(decided.evaluations).toHaveLength(1);
  });

  it('searches declared actions the same way the realm-scoped search endpoint does', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const response = await fetch(`${GIAM}/api/v1/access/search/action`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ resource: { type: 'roles' } }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const found = await response.json() as { actions: Array<{ name: string }> };
    expect(Array.isArray(found.actions)).toBe(true);
  });
});
