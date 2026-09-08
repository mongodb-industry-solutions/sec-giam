/**
 * v43 P3: a pending self-registration can actually be approved.
 *
 * Before this, `PATCH .../Users/:id` special-cased deactivation (`active: false` forces
 * `lifecycleState: 'suspended'`) with no matching case for activation, so setting `active: true` on
 * a principal awaiting approval left `lifecycleState: 'pending'` untouched: the record ended up
 * `active: true` and `lifecycleState: 'pending'` at once, and there was no correct way to approve a
 * pending account through provisioning at all.
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

async function managerToken(): Promise<string> {
  return runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
}

describe('v43: approving a self-registered account', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('lands pending, and a PATCH cannot leave it inconsistent', async () => {
    if (!live) return;

    const userName = `pending-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/realms/leafypay/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Correct-Horse-1' }),
      signal: AbortSignal.timeout(20000),
    });
    expect(registered.status).toBe(200);
    const created = await registered.json() as { subjectId: string; status: string };
    expect(created.status).toBe('pending');

    const token = await managerToken();
    expect(token, 'the manager could not sign in').toBeTruthy();
    const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

    const approved = await fetch(`${GIAM}/realms/leafypay/scim/v2/Users/${created.subjectId}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({
        schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        Operations: [{ op: 'replace', value: { active: true } }],
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(approved.status).toBe(200);
    const user = await approved.json() as {
      active: boolean;
      'urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal'?: { lifecycleState?: string; domainId?: string };
    };
    expect(user.active).toBe(true);
    // The bug: `lifecycleState` stayed `pending` here, which is `active: true` and `pending` at once.
    const extension = user['urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal'];
    expect(extension?.lifecycleState).toBe('active');
    // v43: self-registration used to leave `domainId` unset entirely, so the console could never say
    // which directory a principal belonged to. It resolves through the realm's local domain now.
    expect(extension?.domainId, 'self-registration should attribute the principal to a directory').toBeTruthy();

    const listedPending = await fetch(
      `${GIAM}/realms/leafypay/scim/v2/Users?pending=true`,
      { headers, signal: AbortSignal.timeout(20000) },
    );
    expect(listedPending.status).toBe(200);
    const pendingList = await listedPending.json() as { Resources: Array<{ id: string }> };
    expect(pendingList.Resources.map((resource) => resource.id)).not.toContain(created.subjectId);
  });
});
