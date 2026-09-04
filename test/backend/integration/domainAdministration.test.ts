/**
 * Administering the authentication paths of a realm. ADR-002.
 *
 * ADR-001 made `domain` a collection and moved the realm's authentication configuration onto it,
 * and for two iterations nothing could edit it. The console had the whole surface and called a
 * route that existed in no service.
 *
 * Three claims are worth a test rather than a reading, and each is a different kind of failure:
 * the settings a console receives must never include a secret or a reference to one; the last way
 * into a realm must not be removable; and a caller without the permission must be refused rather
 * than shown a filtered list.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const REALM = 'leafypay';
const CONSOLE = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

/** A real token for a persona, through the whole flow including the consent step. */
async function tokenFor(login: string): Promise<string> {
  const session = await fetch(`${GIAM}/realms/${REALM}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login, password: DEMO_PASSWORD }),
    signal: AbortSignal.timeout(20000),
  });
  if (!session.ok) return '';
  const { sessionId } = await session.json() as { sessionId: string };

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const ask = async (consentGranted: boolean) => fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth`, {
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

describe('ADR-002: administering authentication paths', () => {
  let live = false;
  let manager = '';
  let customer = '';

  /**
   * Every path this suite creates, removed afterwards WHATEVER happened.
   *
   * An earlier version deleted at the end of each test, so a failing assertion left the probe
   * behind: two of them then broke a roster suite and a domain suite that had every right to
   * assume the realm was as it was seeded. A test that can pollute shared state on failure is a
   * test that makes other tests lie.
   */
  const created: string[] = [];

  beforeAll(async () => {
    live = await reachable();
    if (!live) return;
    manager = await tokenFor('alex.rivera');
    customer = await tokenFor('luis.fernandez');
  }, 90_000);

  /** A request that carries a body. */
  function headers(token: string) {
    return { authorization: `Bearer ${token}`, 'content-type': 'application/json' };
  }

  /**
   * A request that carries NONE.
   *
   * Declaring a JSON content type on a GET or a DELETE and sending nothing is a 400 from the body
   * parser, correctly: an empty body is not valid JSON. Real clients do not do it and neither does
   * this suite.
   */
  function authOnly(token: string) {
    return { authorization: `Bearer ${token}` };
  }

  /** Creates a probe path and remembers it for cleanup. */
  async function createProbe(body: Record<string, unknown>): Promise<Response> {
    const response = await fetch(`${GIAM}/realms/${REALM}/domains`, {
      method: 'POST',
      headers: headers(manager),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });
    if (response.status === 201) {
      const clone = await response.clone().json() as { providerId?: string };
      if (clone.providerId) created.push(clone.providerId);
    }
    return response;
  }

  afterAll(async () => {
    if (!live) return;
    for (const providerId of created) {
      await fetch(`${GIAM}/realms/${REALM}/domains/${providerId}`, {
        method: 'DELETE', headers: authOnly(manager), signal: AbortSignal.timeout(20000),
      }).catch(() => null);
    }
  }, 60_000);

  it('lists the paths of the realm to a caller holding the permission', async () => {
    if (!live) return;
    expect(manager, 'the manager could not sign in').toBeTruthy();

    const response = await fetch(`${GIAM}/realms/${REALM}/domains`, { headers: authOnly(manager), signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(200);

    const { items, total } = await response.json() as { items: Array<{ name: string; protocol: string }>; total: number };
    expect(total).toBeGreaterThan(0);
    /**
     * The realm's own directory is always present: ADR-001 guarantees exactly one per realm.
     *
     * Asserted by PROTOCOL rather than by slug. The slug is a label an operator may change, and it
     * was changed from `local` to `atlas-id`; what must hold is that exactly one internal path
     * exists, which is the actual guarantee.
     */
    const internal = items.filter((item) => item.protocol === 'internal');
    expect(internal).toHaveLength(1);
  });

  it('publishes NO secret and NO reference to one', async () => {
    if (!live) return;
    /**
     * The disclosure this endpoint is most likely to cause, asserted rather than reviewed.
     *
     * `config` carries an open index signature, so a generous read would hand a console whatever an
     * adapter had written there. The published set is an allowlist, and `clientSecretRef` is
     * outside it: a console needs to know WHETHER a secret is configured, which is a boolean, and
     * never which one.
     */
    const response = await fetch(`${GIAM}/realms/${REALM}/domains`, { headers: authOnly(manager), signal: AbortSignal.timeout(20000) });
    const body = await response.text();

    expect(body).not.toContain('clientSecretRef');
    expect(body).not.toContain('clientSecret"');

    const { items } = JSON.parse(body) as { items: Array<{ config: Record<string, unknown>; hasClientSecret: boolean }> };
    for (const item of items) {
      expect(Object.keys(item.config)).not.toContain('clientSecretRef');
      // The question a console legitimately asks is still answerable.
      expect(typeof item.hasClientSecret).toBe('boolean');
    }
  });

  it('refuses a caller without the permission, rather than filtering the answer', async () => {
    if (!live) return;
    expect(customer, 'the customer could not sign in').toBeTruthy();

    // An ordinary account holder has no business reading how a realm authenticates people. A 200
    // with an empty list would say the surface exists and they hold none of it, which is a
    // different and untrue statement.
    const response = await fetch(`${GIAM}/realms/${REALM}/domains`, { headers: authOnly(customer), signal: AbortSignal.timeout(20000) });
    expect(response.status).toBe(403);
  });

  it('creates a path DISABLED, so it authenticates nobody before it is checked', async () => {
    if (!live) return;
    const name = `probe-${randomBytes(4).toString('hex')}`;

    const made = await createProbe({ name, displayName: 'Probe provider', protocol: 'oidc' });
    expect(made.status).toBe(201);

    const domain = await made.json() as { providerId: string; enabled: boolean; adapter: string };
    // The default that matters: a path live the moment it is created, before anybody has checked
    // its settings, would authenticate people against a half-configured upstream.
    expect(domain.enabled).toBe(false);
    // And it resolved its own adapter, so an operator does not have to name the code that runs it.
    expect(domain.adapter).toBe('oidc');

    const duplicate = await createProbe({ name, displayName: 'Same slug', protocol: 'oidc' });
    // The slug is what home-realm discovery resolves on, so a duplicate would make which path
    // answers depend on document order.
    expect(duplicate.status).toBe(409);

    const removed = await fetch(`${GIAM}/realms/${REALM}/domains/${domain.providerId}`, {
      method: 'DELETE',
      headers: authOnly(manager),
      signal: AbortSignal.timeout(20000),
    });
    expect(removed.status).toBe(200);
  });

  it('merges config rather than replacing it, so a round trip cannot drop a secret reference', async () => {
    if (!live) return;
    const name = `probe-${randomBytes(4).toString('hex')}`;
    const made = await createProbe({
      name,
      displayName: 'Probe provider',
      protocol: 'oidc',
      config: { issuer: 'https://upstream.example', clientSecretRef: 'vault://probe' },
    });
    const { providerId } = await made.json() as { providerId: string };

    /**
     * The console sends back what it SAW, which never included the secret reference.
     *
     * A wholesale assignment would then delete the reference as a side effect of saving an
     * unrelated field, and the provider would stop working for a reason nothing in the request
     * mentioned.
     */
    const updated = await fetch(`${GIAM}/realms/${REALM}/domains/${providerId}`, {
      method: 'PATCH',
      headers: headers(manager),
      body: JSON.stringify({ config: { issuer: 'https://upstream.example/v2' } }),
      signal: AbortSignal.timeout(20000),
    });
    expect(updated.status).toBe(200);

    const view = await updated.json() as { config: { issuer?: string }; hasClientSecret: boolean };
    expect(view.config.issuer).toBe('https://upstream.example/v2');
    expect(view.hasClientSecret, 'the secret reference was dropped by an unrelated write').toBe(true);

    await fetch(`${GIAM}/realms/${REALM}/domains/${providerId}`, {
      method: 'DELETE', headers: authOnly(manager), signal: AbortSignal.timeout(20000),
    });
  });

  it('will not let the last way in be removed or disabled', async () => {
    if (!live) return;
    /**
     * The one irreversible mistake this surface makes possible.
     *
     * A realm with no enabled path cannot be signed into, including by the administrator who would
     * undo it, and no amount of holding the right permission helps afterwards. So it is refused
     * here rather than warned about in a console.
     */
    const listed = await fetch(`${GIAM}/realms/${REALM}/domains`, { headers: authOnly(manager), signal: AbortSignal.timeout(20000) });
    const { items } = await listed.json() as { items: Array<{ providerId: string; name: string; enabled: boolean }> };
    const enabled = items.filter((item) => item.enabled);

    // Disable every enabled path but one, then assert the last is protected. Each disable is undone
    // afterwards, so the realm is left exactly as it was found.
    const toRestore: string[] = [];
    try {
      for (const path of enabled.slice(1)) {
        const off = await fetch(`${GIAM}/realms/${REALM}/domains/${path.providerId}`, {
          method: 'PATCH', headers: headers(manager), body: JSON.stringify({ enabled: false }),
          signal: AbortSignal.timeout(20000),
        });
        expect(off.status).toBe(200);
        toRestore.push(path.providerId);
      }

      const last = enabled[0].providerId;
      const disable = await fetch(`${GIAM}/realms/${REALM}/domains/${last}`, {
        method: 'PATCH', headers: headers(manager), body: JSON.stringify({ enabled: false }),
        signal: AbortSignal.timeout(20000),
      });
      expect(disable.status, 'the last enabled path could be disabled').toBe(409);

      const remove = await fetch(`${GIAM}/realms/${REALM}/domains/${last}`, {
        method: 'DELETE', headers: authOnly(manager), signal: AbortSignal.timeout(20000),
      });
      expect(remove.status, 'the last enabled path could be deleted').toBe(409);
    } finally {
      for (const providerId of toRestore) {
        await fetch(`${GIAM}/realms/${REALM}/domains/${providerId}`, {
          method: 'PATCH', headers: headers(manager), body: JSON.stringify({ enabled: true }),
          signal: AbortSignal.timeout(20000),
        }).catch(() => null);
      }
    }
  });

  it('keeps self-registration on the path that can offer it, and nowhere else', async () => {
    if (!live) return;
    /**
     * ADR-002. It sat on the realm, describing the internal directory while claiming to describe
     * the realm, and nobody self-registers into a federated upstream.
     */
    const listed = await fetch(`${GIAM}/realms/${REALM}/domains`, { headers: authOnly(manager), signal: AbortSignal.timeout(20000) });
    const { items } = await listed.json() as { items: Array<{ name: string; protocol: string; registration?: unknown }> };

    const internal = items.find((item) => item.protocol === 'internal');
    expect(internal?.registration, 'the internal path carries no registration rule').toBeTruthy();
    for (const federated of items.filter((item) => item.protocol !== 'internal')) {
      expect(federated.registration, `${federated.name} claims a registration rule it cannot honour`).toBeUndefined();
    }
  });
});
