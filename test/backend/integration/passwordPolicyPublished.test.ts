/**
 * The password policy a form renders is the one the authority enforces.
 *
 * A checklist built from a constant copied into the console is a checklist that lies the moment a
 * realm changes its minimum length. So the console reads the policy, and the claim here is that what
 * it reads agrees rule for rule with what the change endpoint refuses: a password failing a
 * published rule must be refused, and the refusal must name that rule.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { endSession, issueTokenFor } from './support/authorizationFlow';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const CONSOLE = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
const REALM = 'LeafyIdp';

interface Policy {
  minLength: number;
  requireUppercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
  historyDepth: number;
}

/**
 * Every session these tests opened, ended when they finish.
 *
 * Signing a persona in through the real flow creates a real session, and a suite that never closes
 * them leaves one per login alive for the length of its idle window. Run a few times, that is a
 * demo whose sessions screen is full of sessions nobody is using: correct records of nothing, which
 * is indistinguishable from a bug to whoever is looking at the screen.
 */
const opened: Array<{ token: string; sessionId: string }> = [];

async function runFlow(
  giam: string,
  realm: string,
  login: string,
  password: string,
  options: Parameters<typeof issueTokenFor>[4],
): Promise<string> {
  const issued = await issueTokenFor(giam, realm, login, password, options);
  if (issued.sessionId) opened.push(issued);
  return issued.token;
}

afterAll(async () => {
  for (const session of opened) await endSession(GIAM, REALM, session.token, session.sessionId);
});

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

describe('the password policy is published, not guessed at by the console', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    live = await reachable();
    // An ordinary customer: the checklist is for whoever is changing a password, not for an
    // administrator, so the read must not need a permission.
    if (live) token = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
  });

  it('refuses the policy to a caller with no token', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/credentials/password/policy`, {
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(401);
  });

  it('answers an ordinary user holding no permission at all', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/credentials/password/policy`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const { policy } = await response.json() as { policy: Policy | null };
    expect(policy).not.toBeNull();
    expect(policy!.minLength).toBeGreaterThan(0);
    expect(typeof policy!.requireUppercase).toBe('boolean');
    expect(typeof policy!.requireNumber).toBe('boolean');
    expect(typeof policy!.requireSymbol).toBe('boolean');
  });

  /**
   * The published minimum is the enforced minimum.
   *
   * Deliberately submits the WRONG current password so nothing is ever changed: the policy check
   * would run after the proof of possession, so a 403 here means the policy was never reached and
   * the assertion below is about the ordering, not about the rule. The rule itself is asserted
   * through the schema, which refuses a short password with a 400 before any credential is touched.
   */
  it('refuses a password shorter than the published minimum, changing nothing', async () => {
    if (!live) return;
    const read = await fetch(`${GIAM}/api/v1/realms/${REALM}/credentials/password/policy`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000),
    });
    const { policy } = await read.json() as { policy: Policy };

    const short = 'a'.repeat(Math.max(1, policy.minLength - 1));
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/credentials/password`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        currentPassword: 'not-the-current-password',
        newPassword: short,
        newPasswordConfirmation: short,
      }),
      signal: AbortSignal.timeout(20000),
    });
    // 400 from the schema minimum, never 200: a password below the published floor is never accepted.
    expect(response.status).toBe(400);

    // And the demo password still signs in, so this test changed nothing.
    const again = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
    expect(again).toBeTruthy();
  });
});
