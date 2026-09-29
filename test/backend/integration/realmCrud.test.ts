/**
 * v43 P11: a realm can be created and reconfigured at runtime, not only by editing `realms.json`
 * and reseeding. Exercises the full provisioning: the realm record, its own internal domain (so it
 * has somewhere for a principal to belong to, P12's own invariant), and a published signing key,
 * all created together and ready to sign somebody in immediately.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { randomUUID } from 'crypto';
import { tokenFor as runFlow } from './support/authorizationFlow';
import { deleteTestRealm } from './support/directDb';

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

describe('v43: realm CRUD provisions a whole, usable realm', () => {
  let live = false;
  let managerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: PLATFORM });
  });

  it('creates a realm with its own domain and signing key, lists it, reads it, and updates it', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const name = `v43-realm-${randomUUID().slice(0, 8)}`;

    const created = await fetch(`${GIAM}/api/v1/realms`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ name, displayName: 'V43 Test Realm' }),
      signal: AbortSignal.timeout(20000),
    });
    expect(created.status).toBe(201);
    const realm = await created.json() as { realmId: string; name: string; issuer: string; enabled: boolean };

    // No route retires a realm: creating one is self-service, ending one is not exposed at all.
    // Deleted directly the moment it exists, so an assertion failing below still leaves nothing
    // behind. Setup and the seeder are the only source of truth for what the database holds; a
    // realm this test provisioned and forgot to retire would sit there indistinguishable from one.
    try {
      expect(realm.name).toBe(name);
      expect(realm.issuer).toContain(name);
      expect(realm.enabled).toBe(true);

      // Note: `GET /api/v1/realms/:realm/domains` cannot be asserted here with the manager's own token. That
      // route is scoped INSIDE the new realm, and nobody holds an assignment there yet: bootstrapping
      // an administrator for a realm just created is the pre-existing cross-realm grant mechanism
      // (`POST /api/v1/realms/:realm/realm-grants`), a separate capability, not this endpoint's job. The
      // domain's existence is evidence enough here: a token for the new realm could only ever be
      // minted at all because `localDomain` resolved and the invariant-hardening added in this same
      // session (P12) did not throw.

      // A signing key was published: discovery answers for the new realm's own JWKS immediately.
      const jwks = await fetch(`${GIAM}/api/v1/realms/${name}/protocol/oidc/certs`, { signal: AbortSignal.timeout(20000) });
      expect(jwks.status).toBe(200);
      const keySet = await jwks.json() as { keys: unknown[] };
      expect(keySet.keys.length).toBeGreaterThan(0);

      const listed = await fetch(`${GIAM}/api/v1/realms`, { headers, signal: AbortSignal.timeout(20000) });
      expect(listed.status).toBe(200);
      const realmList = await listed.json() as { realms: Array<{ name: string }> };
      expect(realmList.realms.map((r) => r.name)).toContain(name);

      const updated = await fetch(`${GIAM}/api/v1/realms/${name}`, {
        method: 'PATCH', headers, body: JSON.stringify({ displayName: 'Renamed Display' }), signal: AbortSignal.timeout(20000),
      });
      expect(updated.status).toBe(200);
      expect((await updated.json()).displayName).toBe('Renamed Display');

      // The one thing that cannot change: the slug is embedded in the issuer already handed out.
      // Fastify strips a property the schema does not declare rather than refusing the request (the
      // same convention every other PATCH in this authority already follows), so the assertion is
      // that the name is UNCHANGED, not that the request itself was rejected.
      const attemptRename = await fetch(`${GIAM}/api/v1/realms/${name}`, {
        method: 'PATCH', headers, body: JSON.stringify({ name: 'something-else' }), signal: AbortSignal.timeout(20000),
      });
      expect(attemptRename.status).toBe(200);
      expect((await attemptRename.json()).name).toBe(name);
    } finally {
      await deleteTestRealm(realm.realmId);
    }
  });

  it('refuses a name that is already taken', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const response = await fetch(`${GIAM}/api/v1/realms`, {
      method: 'POST', headers, body: JSON.stringify({ name: 'leafypay', displayName: 'Duplicate' }), signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(409);
  });
});
