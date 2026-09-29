/**
 * v43 P9: a domain can switch CIBA off for the principals identified through it.
 *
 * Scoped to the IDENTIFIED PRINCIPAL's own domain, not the calling client: CIBA authenticates a
 * person, and which paths may authenticate that person is what a domain already governs for every
 * other method. `client_credentials` has no equivalent, since it authenticates a workload with no
 * domain in the request at all.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { randomUUID } from 'crypto';
import { tokenFor as runFlow } from './support/authorizationFlow';
import { deleteTestPrincipal } from './support/directDb';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const PLATFORM = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
// The one seeded client actually registered for the CIBA grant (clients.json).
const WALLET_CLIENT_ID = 'f1dc0169-4f90-402c-adc8-f7e2c5c0fc7d';
const WALLET_SECRET = 'ZgGxaRICNAQbkJflGt5G_B3XIcmCrSYGRJ55C5G1KRU';

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

async function tryCiba(userName: string): Promise<{ error?: string }> {
  const response = await fetch(`${GIAM}/api/v1/realms/leafypay/protocol/oidc/ext/ciba/auth`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${Buffer.from(`${WALLET_CLIENT_ID}:${WALLET_SECRET}`).toString('base64')}`,
    },
    body: new URLSearchParams({ login_hint: userName, scope: 'openid' }).toString(),
    signal: AbortSignal.timeout(20000),
  });
  return response.json() as Promise<{ error?: string }>;
}

describe('v43: CIBA is gated by the identified principal\'s own domain', () => {
  let live = false;
  let managerToken = '';
  let domainId = '';
  let userName = '';
  let subjectId = '';

  beforeAll(async () => {
    live = await reachable();
    if (!live) return;
    managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });

    // A fresh registration, on this realm's own local domain (v43's earlier fix), approved so it is
    // a real active principal rather than a pending one.
    userName = `ciba-gate-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/api/v1/realms/leafypay/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Correct-Horse-1' }),
      signal: AbortSignal.timeout(20000),
    });
    const created = await registered.json() as { subjectId: string };
    subjectId = created.subjectId;
    const approveHeaders = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const approved = await fetch(`${GIAM}/api/v1/realms/leafypay/scim/Users/${created.subjectId}`, {
      method: 'PATCH',
      headers: approveHeaders,
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'replace', value: { active: true } }],
      }),
      signal: AbortSignal.timeout(20000),
    });
    const user = await approved.json() as { 'urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal'?: { domainId?: string } };
    domainId = user['urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal']?.domainId ?? '';
  });

  // No route retires a registered principal; deleted directly so this test does not leave one
  // behind on every run.
  afterAll(async () => {
    if (subjectId) await deleteTestPrincipal(subjectId).catch(() => {});
  });

  it('refuses before the credential check when the domain switches CIBA off, and allows it back on', async () => {
    if (!live) return;
    expect(domainId, 'the registered principal should carry a domainId (v43 fix)').toBeTruthy();
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

    // Restored regardless of what the assertions below do: this domain is the realm's SHARED one,
    // so leaving CIBA switched off here would refuse it for everybody else too, not just this test.
    try {
      // A principal with no registered device key still reaches the domain gate FIRST: turned off,
      // the refusal is the domain's, not "no authenticator".
      const off = await fetch(`${GIAM}/api/v1/realms/leafypay/domains/${domainId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ authentication: { cibaEnabled: false } }), signal: AbortSignal.timeout(20000),
      });
      expect(off.status).toBe(200);

      const refused = await tryCiba(userName);
      expect(refused.error).toBe('unauthorized_client');

      const on = await fetch(`${GIAM}/api/v1/realms/leafypay/domains/${domainId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ authentication: { cibaEnabled: true } }), signal: AbortSignal.timeout(20000),
      });
      expect(on.status).toBe(200);

      const allowedPastTheGate = await tryCiba(userName);
      // Falls through to the credential check now: this principal has no device key, so the refusal
      // changes to that instead of the domain's.
      expect(allowedPastTheGate.error).not.toBe('unauthorized_client');
    } finally {
      await fetch(`${GIAM}/api/v1/realms/leafypay/domains/${domainId}`, {
        method: 'PATCH', headers, body: JSON.stringify({ authentication: { cibaEnabled: true } }), signal: AbortSignal.timeout(20000),
      }).catch(() => {});
    }
  });
});
