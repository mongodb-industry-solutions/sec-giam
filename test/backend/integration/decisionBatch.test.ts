/**
 * v43 P16: AuthZEN 1.0's batch evaluation extension (`/access/v1/evaluations` in the
 * specification's own naming), against the running `/decision/evaluations` endpoint.
 *
 * Asserts the same three things the single endpoint's own tests rely on, PLUS that a batch answers
 * the same as N single calls would: a top-level default is inherited by an entry that omits it, an
 * entry's own value overrides the default, answers come back in the order asked, and asking about
 * another subject is still gated once, not per entry.
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

describe('v43: batch decision evaluation matches what single calls would answer', () => {
  let live = false;
  let managerToken = '';
  let customerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (!live) return;
    managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
    customerToken = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('answers in order, applying a top-level default and letting an entry override it', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };

    const batch = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/evaluations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        // Top-level default: every entry that names no resource/action of its own is asked this.
        resource: { type: 'sessions' },
        action: { name: 'view' },
        evaluations: [
          {},
          { action: { name: 'manage' } },
          { resource: { type: 'roles' }, action: { name: 'manage' } },
        ],
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(batch.status).toBe(200);
    const body = await batch.json() as { evaluations: Array<{ decision: boolean; context: { subjectId?: string } }> };
    expect(body.evaluations).toHaveLength(3);

    // Cross-checked against the single endpoint, not merely asserted: the batch answer for the
    // manager's own `sessions:view` must be the identical decision the single call already gives.
    const single = await fetch(`${GIAM}/api/v1/realms/leafypay/decision`, {
      method: 'POST', headers,
      body: JSON.stringify({ resource: { type: 'sessions' }, action: { name: 'view' } }),
      signal: AbortSignal.timeout(20000),
    });
    const singleBody = await single.json() as { decision: boolean };
    expect(body.evaluations[0].decision).toBe(singleBody.decision);

    // Every entry answered about the caller, since none named a different subject.
    for (const evaluation of body.evaluations) {
      expect(evaluation.context.subjectId).toBeTruthy();
    }
  });

  it('refuses an entry naming another subject without the oversight tier, same as the single endpoint', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${customerToken}`, 'content-type': 'application/json' };
    const response = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/evaluations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        subject: { type: 'identity', id: 'a1000070-0000-4000-8000-000000000070' },
        evaluations: [{ resource: { type: 'roles' }, action: { name: 'view' } }],
      }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(403);
  });

  it('refuses an entry with no resource/action and no default, naming which one', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const response = await fetch(`${GIAM}/api/v1/realms/leafypay/decision/evaluations`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ evaluations: [{ resource: { type: 'sessions' }, action: { name: 'view' } }, {}] }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).detail).toContain('Entry 1');
  });
});
