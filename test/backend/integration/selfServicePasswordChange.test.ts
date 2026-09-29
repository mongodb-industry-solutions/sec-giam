/**
 * A principal changing their own password: the current one proves the request, and the new one is
 * what signs them in afterwards. The self-service counterpart of `passwordReset.test.ts`, which
 * covers the administrative path.
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

/** A fresh, approved, signed-in test principal, so each test starts from its own account. */
async function newApprovedPrincipal(password: string): Promise<{ subjectId: string; userName: string; token: string }> {
  const userName = `selfpw-${randomUUID().slice(0, 8)}`;
  const registered = await fetch(`${GIAM}/realms/leafypay/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ userName, password }),
    signal: AbortSignal.timeout(20000),
  });
  const created = await registered.json() as { subjectId: string };

  // `leafypay` does not auto-approve self-registration (see `passwordReset.test.ts`), so a login
  // attempt would 401 on lifecycle state alone, before this endpoint is ever reached.
  const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
  await fetch(`${GIAM}/realms/leafypay/scim/v2/Users/${created.subjectId}`, {
    method: 'PATCH',
    headers: { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', value: { active: true } }],
    }),
    signal: AbortSignal.timeout(20000),
  });

  const token = await runFlow(GIAM, 'leafypay', userName, password, { client: PLATFORM });
  return { subjectId: created.subjectId, userName, token };
}

// Each test runs two full sign-in flows and several password hashes, which under parallel workers
// sits right at the global 30s limit.
describe('a principal changes their own password', { timeout: 90_000 }, () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('the new password signs in, the old one no longer does', async () => {
    if (!live) return;
    const principal = await newApprovedPrincipal('Original-Pass-1');

    try {
      const changed = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${principal.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'Original-Pass-1',
          newPassword: 'Replaced-Pass-2',
          newPasswordConfirmation: 'Replaced-Pass-2',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(changed.status).toBe(200);
      expect((await changed.json()).changed).toBe(true);

      const oldLogin = await fetch(`${GIAM}/realms/leafypay/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ login: principal.userName, password: 'Original-Pass-1' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(oldLogin.status).toBe(401);

      const newLogin = await fetch(`${GIAM}/realms/leafypay/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ login: principal.userName, password: 'Replaced-Pass-2' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(newLogin.status).toBe(200);
    } finally {
      await deleteTestPrincipal(principal.subjectId);
    }
  });

  it('refuses a current password that does not match, and changes nothing', async () => {
    if (!live) return;
    const principal = await newApprovedPrincipal('Original-Pass-1');

    try {
      const attempt = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${principal.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'Wrong-Guess-9',
          newPassword: 'Replaced-Pass-2',
          newPasswordConfirmation: 'Replaced-Pass-2',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(attempt.status).toBe(403);

      const stillOriginal = await fetch(`${GIAM}/realms/leafypay/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ login: principal.userName, password: 'Original-Pass-1' }),
        signal: AbortSignal.timeout(20000),
      });
      expect(stillOriginal.status).toBe(200);
    } finally {
      await deleteTestPrincipal(principal.subjectId);
    }
  });

  it('refuses a new password that does not match its own confirmation', async () => {
    if (!live) return;
    const principal = await newApprovedPrincipal('Original-Pass-1');

    try {
      const attempt = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${principal.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'Original-Pass-1',
          newPassword: 'Replaced-Pass-2',
          newPasswordConfirmation: 'Typo-Pass-2',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(attempt.status).toBe(400);
    } finally {
      await deleteTestPrincipal(principal.subjectId);
    }
  });

  it('refuses a new password identical to the current one', async () => {
    if (!live) return;
    const principal = await newApprovedPrincipal('Original-Pass-1');

    try {
      const attempt = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${principal.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'Original-Pass-1',
          newPassword: 'Original-Pass-1',
          newPasswordConfirmation: 'Original-Pass-1',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(attempt.status).toBe(400);
    } finally {
      await deleteTestPrincipal(principal.subjectId);
    }
  });

  it('refuses a password under the eight-character floor', async () => {
    if (!live) return;
    const principal = await newApprovedPrincipal('Original-Pass-1');

    try {
      const attempt = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
        method: 'POST',
        headers: { authorization: `Bearer ${principal.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          currentPassword: 'Original-Pass-1',
          newPassword: 'short1',
          newPasswordConfirmation: 'short1',
        }),
        signal: AbortSignal.timeout(20000),
      });
      expect(attempt.status).toBe(400);
    } finally {
      await deleteTestPrincipal(principal.subjectId);
    }
  });

  it('refuses an unauthenticated request', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/realms/leafypay/credentials/password`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        currentPassword: 'whatever',
        newPassword: 'Replaced-Pass-2',
        newPasswordConfirmation: 'Replaced-Pass-2',
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(401);
  });
});
