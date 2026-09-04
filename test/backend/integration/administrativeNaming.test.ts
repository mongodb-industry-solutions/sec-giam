/**
 * Administrative screens are about PEOPLE, so the surfaces behind them name people.
 *
 * This exists because the same defect was reported twice by the owner: screens identifying somebody
 * as `a1000070-0000-4000-8000-000000000070`. The first instance was the signed-in user's own name in
 * the console header and menu. The second was every list about somebody else: sessions, role
 * assignments and privilege elevations, which carried only a subject id, so the interface had
 * nothing else to render.
 *
 * Asserted at the API rather than in a browser. This is the contract those screens read, the
 * authority has no browser test harness, and a contract test fails for one reason where a rendering
 * test fails for several. What it pins is that the name TRAVELS: a screen cannot show what it was
 * never sent.
 *
 * The subject id is not being replaced. It stays in every payload, because it is what a record is
 * filed under and what an investigation quotes. What changed is that it is no longer the only thing
 * offered when a human being is what the row is about.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';
const CONSOLE = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

/** A real administrator token, through the whole flow including consent. */
async function adminToken(): Promise<string> {
  const session = await fetch(`${GIAM}/realms/${REALM}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login: 'alex.rivera', password: DEMO_PASSWORD }),
    signal: AbortSignal.timeout(20000),
  });
  if (!session.ok) return '';
  const { sessionId } = await session.json() as { sessionId: string };

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const ask = (consentGranted: boolean) => fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: CONSOLE.clientId,
      redirect_uri: CONSOLE.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      session_id: sessionId,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...(consentGranted ? { consent_granted: true } : {}),
    }),
    signal: AbortSignal.timeout(20000),
  });

  let authorize = await ask(false);
  if (!authorize.ok) return '';
  let granted = await authorize.json() as { code?: string; consent_required?: boolean };
  if (granted.consent_required) {
    authorize = await ask(true);
    if (!authorize.ok) return '';
    granted = await authorize.json() as { code?: string };
  }
  if (!granted.code) return '';

  const token = await fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: granted.code,
      redirect_uri: CONSOLE.redirectUri,
      client_id: CONSOLE.clientId,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!token.ok) return '';
  return (await token.json() as { access_token: string }).access_token;
}

/** The identifier the reports objected to, as a shape rather than a specific value. */
const LOOKS_LIKE_A_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

describe('administrative surfaces name the people they are about', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) token = await adminToken();
  }, 90_000);

  function headers() {
    return { authorization: `Bearer ${token}` };
  }

  it('names the holder of every session', async () => {
    if (!live) return;
    expect(token, 'the administrator could not sign in').toBeTruthy();

    const response = await fetch(`${GIAM}/realms/${REALM}/sessions`, { headers: headers(), signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(200);

    const { sessions } = await response.json() as {
      sessions: Array<{ subjectId: string; userName?: string }>;
    };
    // Signing in above created one, so an empty list would mean this proves nothing.
    expect(sessions.length, 'no sessions to check').toBeGreaterThan(0);

    for (const session of sessions) {
      expect(
        session.userName,
        `session held by ${session.subjectId} carries no name, so a screen can only show the id`,
      ).toBeTruthy();
      // The id is still there. It is the detail, not the identity.
      expect(session.subjectId).toBeTruthy();
    }
  });

  it('names the holder of every role assignment', async () => {
    if (!live) return;

    const roles = await fetch(`${GIAM}/realms/${REALM}/roles`, { headers: headers(), signal: AbortSignal.timeout(20000) });
    const { roles: all } = await roles.json() as { roles: Array<{ roleId: string; name: string; assignmentCount?: number }> };
    const held = all.find((role) => (role.assignmentCount ?? 0) > 0);
    expect(held, 'no role has an assignment, so this proves nothing').toBeTruthy();

    const response = await fetch(
      `${GIAM}/realms/${REALM}/roles/${held!.roleId}/assignments`,
      { headers: headers(), signal: AbortSignal.timeout(20000) },
    );
    expect(response.status).toBe(200);

    const body = await response.json() as { assignments?: Array<{ subjectId: string; userName?: string }> };
    const assignments = body.assignments ?? [];
    expect(assignments.length, `role ${held!.name} reported holders and returned none`).toBeGreaterThan(0);

    for (const assignment of assignments) {
      expect(
        assignment.userName,
        `${held!.name} is held by ${assignment.subjectId} with no name attached`,
      ).toBeTruthy();
    }
  });

  it('never offers a bare identifier as the only thing naming somebody', async () => {
    if (!live) return;
    /**
     * The general form of both reports, as one assertion.
     *
     * A payload where the only human-facing field is a uuid leaves an interface no choice: it
     * renders the uuid, and a reviewer scanning the list recognises nobody. Checked on sessions
     * because that surface lists other people by construction.
     */
    const response = await fetch(`${GIAM}/realms/${REALM}/sessions`, { headers: headers(), signal: AbortSignal.timeout(20000) });
    const { sessions } = await response.json() as {
      sessions: Array<{ subjectId: string; userName?: string }>;
    };

    for (const session of sessions) {
      const onlyAnIdentifier = LOOKS_LIKE_A_UUID.test(session.subjectId) && !session.userName;
      expect(
        onlyAnIdentifier,
        `${session.subjectId} is described by nothing but its own id`,
      ).toBe(false);
    }
  });
});
