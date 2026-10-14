/**
 * v43 P4: an administrator setting a new password for a principal, and it actually being the one
 * that signs them in afterwards.
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

describe('v43: an administrator resets a principal\'s password', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('the new password signs in, the old one no longer does', async () => {
    if (!live) return;

    const userName = `reset-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/api/v1/realms/leafypay/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Original-Pass-1' }),
      signal: AbortSignal.timeout(20000),
    });
    expect(registered.status).toBe(200);
    const created = await registered.json() as { subjectId: string };

    try {
      const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
      expect(managerToken).toBeTruthy();
      const authHeaders = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

      // This realm does not auto-approve self-registration: a login attempt would 401 on that alone,
      // which would make the assertion below meaningless. Approved first (v43 P3's own fix), so what
      // is actually being tested here is the password, not the lifecycle state.
      const approved = await fetch(`${GIAM}/api/v1/realms/leafypay/scim/Users/${created.subjectId}`, {
        method: 'PATCH',
        headers: authHeaders,
        body: JSON.stringify({
          schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
          Operations: [{ op: 'replace', value: { active: true } }],
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(approved.status).toBe(200);

      const reset = await fetch(`${GIAM}/api/v1/realms/leafypay/identities/${created.subjectId}/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ password: 'Replaced-Pass-2' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(reset.status).toBe(200);
      expect((await reset.json()).reset).toBe(true);

      const oldLogin = await fetch(`${GIAM}/api/v1/realms/leafypay/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ login: userName, password: 'Original-Pass-1' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(oldLogin.status).toBe(401);

      const newLogin = await fetch(`${GIAM}/api/v1/realms/leafypay/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ login: userName, password: 'Replaced-Pass-2' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(newLogin.status).toBe(200);
    } finally {
      await deleteTestPrincipal(created.subjectId);
    }
    // Seven sequential calls, two of them password hashes: past the 30s default on a busy authority.
  }, 120_000);

  it('refuses a password under the eight-character floor', async () => {
    // `leafypay` seeds no `passwordPolicy` beyond the JSON-schema `minLength: 8` itself (no domain
    // fixture sets `requireUppercase`/`requireNumber`/`requireSymbol`), so this is what there is to
    // assert without inventing a fixture the seed does not carry.
    if (!live) return;
    const userName = `reset-policy-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/api/v1/realms/leafypay/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Original-Pass-1' }),
      signal: AbortSignal.timeout(20000),
    });
    const created = await registered.json() as { subjectId: string };

    try {
      const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
      const response = await fetch(`${GIAM}/api/v1/realms/leafypay/identities/${created.subjectId}/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ password: 'short1' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(400);
    } finally {
      await deleteTestPrincipal(created.subjectId);
    }
  });
});
