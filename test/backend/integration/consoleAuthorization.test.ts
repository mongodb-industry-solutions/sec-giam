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
import { tokenFor as runFlow } from './support/authorizationFlow';

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
  { label: 'manager', realm: 'leafypay', login: 'alex.rivera', ...PLATFORM, views: 'all', manageable: 'all-but-keys', identities: 200 },
  { label: 'security auditor', realm: 'leafypay', login: 'diego.sans', ...PLATFORM, views: 'all', manageable: 'none', identities: 200 },
  { label: 'customer', realm: 'leafypay', login: 'luis.fernandez', ...PLATFORM, views: 'none', manageable: 'none', identities: 403 },
  { label: 'bank administrator', realm: 'leafypay', login: 'samuel.adeyemi', ...BANK, views: 'all', manageable: 'all-but-keys', identities: 200 },
  { label: 'bank compliance', realm: 'leafypay', login: 'ingrid.larsen', ...BANK, views: 'all', manageable: 'none', identities: 200 },
  { label: 'bank customer', realm: 'leafypay', login: 'elena.duarte', ...BANK, views: 'none', manageable: 'none', identities: 403 },
];

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

/**
 * A real access token for a persona, through the ordinary code flow.
 *
 * The flow lives in `support/authorizationFlow` now. This helper had grown its own copy of it,
 * including the two-step consent dance the endpoint used to require, and that copy is what broke
 * when the endpoint became conforming. Each expectation names its own client, so the shared helper
 * takes one.
 */
async function tokenFor(expectation: Expectation): Promise<string> {
  return runFlow(GIAM, expectation.realm, expectation.login, DEMO_PASSWORD, {
    client: { clientId: expectation.clientId, redirectUri: expectation.redirectUri },
  });
}

describe('v39: administering the authority is authorised by role', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('refuses the catalog to a caller with no credential at all', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/api/v1/admin/views`, { signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(401);
  });

  for (const expectation of MATRIX) {
    it(`${expectation.label}: catalog ${expectation.views}, manage ${expectation.manageable}, a view answers ${expectation.identities}`, async () => {
      if (!live) return;

      const token = await tokenFor(expectation);
      expect(token, `${expectation.login} could not sign in`).toBeTruthy();
      const headers = { authorization: `Bearer ${token}` };

      const catalog = await fetch(`${GIAM}/api/v1/admin/views`, { headers, signal: AbortSignal.timeout(20000) });
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

      const guarded = await fetch(`${GIAM}/api/v1/admin/views/identities`, { headers, signal: AbortSignal.timeout(20000) });
      expect(guarded.status).toBe(expectation.identities);
    });
  }
});

/**
 * v42: what `GET /me/permissions` answers, which is what the console's own `can()` falls back to.
 *
 * The access token carries roles rather than entitlements by default, so a screen deciding what to
 * show cannot read the token alone: this endpoint is the console's only reliable source for that
 * decision, and a manager who cannot see `sessions:view` here is a manager whose realm-wide session
 * list silently stays hidden in the UI even though the API would have honoured the request.
 */
describe('v42: a principal reads their own effective permissions, fresh', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('refuses with no credential at all', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/realms/leafypay/me/permissions`, { signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(401);
  });

  it('a manager holds sessions:view and sessions:manage, realm wide', async () => {
    if (!live) return;
    const token = await tokenFor(MATRIX[0]);
    expect(token).toBeTruthy();
    const response = await fetch(`${GIAM}/realms/leafypay/me/permissions`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { permissions: string[]; roles: string[]; scopeKind: string };
    expect(body.scopeKind).toBe('all');
    expect(body.permissions).toContain('sessions:view');
    expect(body.permissions).toContain('sessions:manage');
  });

  it('an ordinary customer holds no authority permission at all', async () => {
    if (!live) return;
    const token = await tokenFor(MATRIX[2]);
    expect(token).toBeTruthy();
    const response = await fetch(`${GIAM}/realms/leafypay/me/permissions`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { permissions: string[]; scopeKind: string };
    expect(body.scopeKind).toBe('self');
    expect(body.permissions).not.toContain('sessions:view');
  });
});
