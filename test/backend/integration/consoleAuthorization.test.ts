/**
 * The console authorises by ROLE, not by a shared credential.
 *
 * Before this, the only way in was an operator token that belongs to whoever holds the environment,
 * which makes administering identity an anonymous act. A person signs in now and what they may reach
 * is decided by the roles they hold.
 *
 * The matrix below is the claim, and each row is a different failure if it breaks: a manager who
 * cannot manage, an auditor who can, or an ordinary customer who can see the directory at all.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';

interface Expectation {
  label: string;
  realm: string;
  login: string;
  clientId: string;
  redirectUri: string;
  /** Views the catalog should offer, and how many of them carry a manage control. */
  views: 'all' | 'none';
  manageable: 'all-but-keys' | 'none';
  /** What a guarded view answers. */
  identities: 200 | 403;
}

const PLATFORM = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
const BANK = { clientId: 'bankcore-console', redirectUri: 'http://localhost:8084/api/auth/callback' };

const MATRIX: Expectation[] = [
  { label: 'manager', realm: 'leafypay', login: 'Alex Rivera', ...PLATFORM, views: 'all', manageable: 'all-but-keys', identities: 200 },
  { label: 'security auditor', realm: 'leafypay', login: 'Diego Sans', ...PLATFORM, views: 'all', manageable: 'none', identities: 200 },
  { label: 'customer', realm: 'leafypay', login: 'Luis Fernandez', ...PLATFORM, views: 'none', manageable: 'none', identities: 403 },
  { label: 'bank administrator', realm: 'bankcore', login: 'Samuel Adeyemi', ...BANK, views: 'all', manageable: 'all-but-keys', identities: 200 },
  { label: 'bank compliance', realm: 'bankcore', login: 'Ingrid Larsen', ...BANK, views: 'all', manageable: 'none', identities: 200 },
  { label: 'bank customer', realm: 'bankcore', login: 'Elena Duarte', ...BANK, views: 'none', manageable: 'none', identities: 403 },
];

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

/** A real access token for a persona, through the ordinary code flow. */
async function tokenFor(expectation: Expectation): Promise<string> {
  const session = await fetch(`${GIAM}/realms/${expectation.realm}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login: expectation.login, password: DEMO_PASSWORD }),
    signal: AbortSignal.timeout(20000),
  });
  if (!session.ok) return '';
  const { sessionId } = await session.json() as { sessionId: string };

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const authorize = await fetch(`${GIAM}/realms/${expectation.realm}/protocol/openid-connect/auth`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: expectation.clientId,
      redirect_uri: expectation.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      session_id: sessionId,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!authorize.ok) return '';
  const { code } = await authorize.json() as { code: string };

  const token = await fetch(`${GIAM}/realms/${expectation.realm}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: expectation.redirectUri,
      client_id: expectation.clientId,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!token.ok) return '';
  return (await token.json() as { access_token: string }).access_token;
}

describe('v39: administering the authority is authorised by role', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('refuses the catalog to a caller with no credential at all', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/admin/views`, { signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(401);
  });

  for (const expectation of MATRIX) {
    it(`${expectation.label}: catalog ${expectation.views}, manage ${expectation.manageable}, a view answers ${expectation.identities}`, async () => {
      if (!live) return;

      const token = await tokenFor(expectation);
      expect(token, `${expectation.login} could not sign in`).toBeTruthy();
      const headers = { authorization: `Bearer ${token}` };

      const catalog = await fetch(`${GIAM}/admin/views`, { headers, signal: AbortSignal.timeout(20000) });
      expect(catalog.status, 'the catalog answers to any authenticated principal').toBe(200);
      const { views } = await catalog.json() as { views: Array<{ name: string; canManage: boolean }> };

      if (expectation.views === 'none') {
        // Nothing listed rather than a list that answers 403 on every click.
        expect(views, 'an ordinary principal is offered no administrative view').toHaveLength(0);
      } else {
        expect(views.length, 'every view is offered').toBeGreaterThan(1);
      }

      const manageable = views.filter((view) => view.canManage);
      if (expectation.manageable === 'none') {
        expect(manageable, 'an auditor may read everything and change nothing').toHaveLength(0);
      } else {
        expect(manageable.length, 'a manager may manage').toBeGreaterThan(1);
        // Signing keys are deliberately view-only: rotation is automatic and the private half never
        // reaches the database, so there is no manage operation to grant.
        expect(manageable.map((view) => view.name)).not.toContain('keys');
      }

      const guarded = await fetch(`${GIAM}/admin/views/identities`, { headers, signal: AbortSignal.timeout(20000) });
      expect(guarded.status).toBe(expectation.identities);
    });
  }
});
