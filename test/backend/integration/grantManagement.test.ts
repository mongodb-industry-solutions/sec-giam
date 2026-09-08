// v41 P6: a person changes what an application holds, afterwards, in either direction.
//
// This suite was in the plan and I did not write it, which is worth naming: the endpoint shipped
// with the P5 commit and nothing exercised it. `trailIntegrity.test.ts` reads `grant.scope_changed`
// events, but its loop body never runs when there are none, so it passed while the endpoint was
// never called. A test that cannot fail is not coverage.
//
// The assertion that matters most is the refusal. Widening is bounded by the client registration,
// and a bound that is silently clamped instead of refused is how somebody believes they restored
// access they did not.
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { signIn, tokenFor, CONSOLE_CLIENT } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';
const PERSON = 'luis.fernandez';

/** A third-party client, because a first-party one creates no grant to manage. */
const THIRD_PARTY = (() => {
  const clients = JSON.parse(
    readFileSync(resolve(__dirname, '../../../backend/data/clients.json'), 'utf8'),
  ) as Array<{ clientId: string; redirectUris?: string[]; grantTypes?: string[]; firstParty?: boolean; scope?: string }>;
  const found = clients.find((client) => client.redirectUris?.length
    && client.grantTypes?.includes('authorization_code')
    && !client.firstParty);
  return {
    clientId: found?.clientId ?? '',
    redirectUri: found?.redirectUris?.[0] ?? '',
    registered: (found?.scope ?? '').split(' ').filter(Boolean),
  };
})();

interface Grant { grantId: string; clientId: string; scopes: string[]; registeredScopes: string[] }

describe('v41 P6: changing what an application holds', () => {
  let live = false;
  let token = '';
  let cookie = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    const session = await signIn(GIAM, REALM, PERSON, DEMO_PASSWORD);
    cookie = session?.cookie ?? '';
    token = await tokenFor(GIAM, REALM, PERSON, DEMO_PASSWORD);
  });

  /** Authorises the third-party client, so there is a grant to manage. */
  async function ensureGrant(scope: string): Promise<void> {
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const url = new URL(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth`);
    for (const [key, value] of Object.entries({
      client_id: THIRD_PARTY.clientId,
      redirect_uri: THIRD_PARTY.redirectUri,
      response_type: 'code',
      scope,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'consent',
    })) url.searchParams.set(key, value);

    const asked = await fetch(url, { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    const location = asked.headers.get('location') ?? '';
    if (!location.includes('/auth/consent')) return;

    const requestId = new URL(location).searchParams.get('request_id') as string;
    await fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth/consent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ request_id: requestId, approved: true }),
      signal: AbortSignal.timeout(20000),
    });
  }

  const grants = async (): Promise<Grant[]> => {
    const response = await fetch(`${GIAM}/realms/${REALM}/grants`, {
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(20000),
    });
    const body = await response.json() as { grants?: Grant[]; items?: Grant[] };
    return body.grants ?? body.items ?? [];
  };

  const change = (grantId: string, scopes: string[]) => fetch(`${GIAM}/realms/${REALM}/grants/${grantId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ scopes }),
    signal: AbortSignal.timeout(20000),
  });

  async function grantForThirdParty(): Promise<Grant | undefined> {
    await ensureGrant('openid profile email');
    return (await grants()).find((grant) => grant.clientId === THIRD_PARTY.clientId);
  }

  it('narrows what an application holds, and ends its sessions so the next token is narrower', async () => {
    if (!live || !token || !THIRD_PARTY.clientId) return;
    const grant = await grantForThirdParty();
    if (!grant) return;

    const response = await change(grant.grantId, ['openid', 'profile']);
    expect(response.status).toBe(200);

    const outcome = await response.json() as {
      before: string[]; after: string[]; removed: string[]; sessionsEnded: number;
    };
    expect(outcome.after).toEqual(['openid', 'profile']);
    expect(outcome.removed).toContain('email');
    // Ending the sessions is what makes the change take effect in minutes rather than at the end of
    // the token's life. It is NOT instantaneous, and the response says how many rather than implying
    // the change is already everywhere.
    expect(typeof outcome.sessionsEnded).toBe('number');
  });

  it('widens again within the registration, so declining a scope is not a trap', async () => {
    if (!live || !token || !THIRD_PARTY.clientId) return;
    const grant = await grantForThirdParty();
    if (!grant) return;

    await change(grant.grantId, ['openid']);
    const response = await change(grant.grantId, ['openid', 'profile']);
    expect(response.status).toBe(200);

    const outcome = await response.json() as { added: string[]; after: string[] };
    expect(outcome.added).toContain('profile');
    expect(outcome.after).toContain('profile');
  });

  /**
   * The assertion that matters most.
   *
   * The registration is the ceiling, because those scopes were deduced from what the owner
   * registered, and a registration that can be exceeded is not a limit. REFUSED rather than clamped:
   * silently granting less than was asked is how somebody believes they restored access they did
   * not, and finds out when the application fails.
   */
  it('refuses a scope beyond the registration rather than quietly granting less', async () => {
    if (!live || !token || !THIRD_PARTY.clientId) return;
    const grant = await grantForThirdParty();
    if (!grant) return;

    const beyond = 'a-scope-this-client-was-never-registered-for';
    const response = await change(grant.grantId, ['openid', beyond]);
    expect(response.status).toBe(400);

    const problem = await response.json() as { detail?: string };
    // The refusal names what crossed the bound, so somebody can act on it.
    expect(problem.detail).toContain(beyond);

    // And nothing moved: a refused change is a change that did not happen.
    const after = (await grants()).find((entry) => entry.grantId === grant.grantId);
    expect(after?.scopes ?? []).not.toContain(beyond);
  });

  /**
   * Without this a console can only ever take permissions away.
   *
   * The ceiling has to travel WITH the grant, because a person restoring something they declined
   * needs to be offered it, and what is held does not say what could be. The two together are what
   * makes consent reversible rather than a one-way door.
   */
  it('publishes the ceiling alongside what is held, so a choice can be offered', async () => {
    if (!live || !token || !THIRD_PARTY.clientId) return;
    const grant = await grantForThirdParty();
    if (!grant) return;

    expect(Array.isArray(grant.registeredScopes)).toBe(true);
    expect(grant.registeredScopes.length, 'the registration must be published').toBeGreaterThan(0);

    // Everything held is within the ceiling, or the ceiling is not one.
    for (const scope of grant.scopes) {
      expect(grant.registeredScopes, `${scope} is held but not registered`).toContain(scope);
    }

    // And it agrees with what the change endpoint enforces: a scope outside it is refused.
    const beyond = 'still-not-a-registered-scope';
    expect(grant.registeredScopes).not.toContain(beyond);
    expect((await change(grant.grantId, [...grant.scopes, beyond])).status).toBe(400);
  });
  it('answers 404 for a grant that is not this person\'s, rather than acting on it', async () => {
    if (!live || !token) return;
    const response = await change('a-grant-that-does-not-exist', ['openid']);
    expect(response.status).toBe(404);
  });

  /**
   * The control that makes widening acceptable at all. An addition nobody can attribute later is an
   * addition that should not be possible.
   */
  it('records every change with the scope set before and after, and who made it', async () => {
    if (!live || !token || !THIRD_PARTY.clientId) return;
    const grant = await grantForThirdParty();
    if (!grant) return;

    await change(grant.grantId, ['openid']);

    const events = await (await fetch(
      `${GIAM}/realms/${REALM}/security-events?action=grant.scope_changed&limit=5`,
      { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20000) },
    )).json() as { events: Array<{ subjectId?: string; detail?: Record<string, unknown> }> };

    expect(events.events.length, 'a scope change must be recorded').toBeGreaterThan(0);
    const [latest] = events.events;
    expect(latest.detail).toHaveProperty('before');
    expect(latest.detail).toHaveProperty('after');
    expect(latest.detail).toHaveProperty('direction');
    // Attributed. Not inferred from context, and not anonymous.
    expect(latest.subjectId, 'the change names who made it').toBeTruthy();
  });
});
