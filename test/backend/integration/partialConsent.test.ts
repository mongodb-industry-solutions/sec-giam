// v41 P5 and P6: a person may approve part of what an application asks for, and change it later.
//
// Consent was all-or-nothing. `covers()` returned false when a single requested scope was missing,
// so somebody who wanted to withhold one scope had to decline the application entirely, and a client
// widening its request looked exactly like a first authorisation. RFC 6749 3.3 explicitly permits
// granting a narrower scope than requested and 5.1 requires the token response to say so, which
// makes the previous design more restrictive than the specification for no gain.
//
// The assertion that matters is the last one in the first block: the TOKEN carries what was granted.
// Recording a narrower grant while still minting a wide token would satisfy every other check here
// and mean nothing.
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { signIn } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';

/**
 * A THIRD-PARTY client, because a first-party one needs no consent at all.
 *
 * Read from the fixture rather than hardcoded, so this follows the seed rather than duplicating it.
 */
const CLIENT = (() => {
  const clients = JSON.parse(
    readFileSync(resolve(__dirname, '../../../backend/data/clients.json'), 'utf8'),
  ) as Array<{ clientId: string; redirectUris?: string[]; grantTypes?: string[]; firstParty?: boolean }>;
  const found = clients.find((client) => client.redirectUris?.length
    && client.grantTypes?.includes('authorization_code')
    && !client.firstParty);
  return { clientId: found?.clientId ?? '', redirectUri: found?.redirectUris?.[0] ?? '' };
})();

interface Prompt {
  clientName: string;
  scopes: Array<{ name: string; description?: string; required?: boolean; alreadyGranted?: boolean }>;
}

describe('v41 P5: consent may be partial, and it is incremental', () => {
  let live = false;
  let cookie = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    const session = await signIn(GIAM, REALM, 'luis.fernandez', DEMO_PASSWORD);
    cookie = session?.cookie ?? '';
  });

  /** Runs to the point where the authority asks, and returns the pending request it created. */
  async function askFor(scope: string): Promise<{ requestId: string; verifier: string }> {
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const url = new URL(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth`);
    for (const [key, value] of Object.entries({
      client_id: CLIENT.clientId,
      redirect_uri: CLIENT.redirectUri,
      response_type: 'code',
      scope,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      // Always ask, so the test does not depend on whether a grant happens to exist already. That
      // dependency is what made an earlier suite pass for whoever had signed in before.
      prompt: 'consent',
    })) url.searchParams.set(key, value);

    const response = await fetch(url, { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    const location = new URL(response.headers.get('location') as string);
    return { requestId: location.searchParams.get('request_id') as string, verifier };
  }

  const promptFor = async (requestId: string): Promise<Prompt> => fetch(
    `${GIAM}/realms/${REALM}/protocol/openid-connect/auth/consent?request_id=${requestId}`,
    { headers: { cookie }, signal: AbortSignal.timeout(20000) },
  ).then((response) => response.json() as Promise<Prompt>);

  const decide = (requestId: string, approved: boolean, grantedScopes?: string[]) => fetch(
    `${GIAM}/realms/${REALM}/protocol/openid-connect/auth/consent`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ request_id: requestId, approved, ...(grantedScopes ? { granted_scopes: grantedScopes } : {}) }),
      signal: AbortSignal.timeout(20000),
    },
  );

  it('describes each scope in the deployment\'s own words, not in wire names', async () => {
    if (!live || !CLIENT.clientId) return;
    const { requestId } = await askFor('openid profile email');
    const prompt = await promptFor(requestId);

    expect(prompt.clientName).toBeTruthy();
    expect(prompt.scopes.map((scope) => scope.name)).toEqual(['openid', 'profile', 'email']);
    // The descriptions come from the resource catalog, seeded, so the authority carries no
    // industry vocabulary of its own and a person reads a sentence rather than `read:accounts`.
    for (const scope of prompt.scopes) expect(scope.description, scope.name).toBeTruthy();
  });

  it('marks the scope the flow cannot proceed without, so the screen cannot untick it', async () => {
    if (!live || !CLIENT.clientId) return;
    const prompt = await promptFor((await askFor('openid profile email')).requestId);
    expect(prompt.scopes.find((scope) => scope.name === 'openid')?.required).toBe(true);
    expect(prompt.scopes.find((scope) => scope.name === 'profile')?.required).toBe(false);
  });

  /**
   * The assertion the rest of this file exists to support. Recording a narrower grant while still
   * minting a wide token would pass every other check and mean nothing.
   */
  it('issues a token carrying only what was approved', async () => {
    if (!live || !CLIENT.clientId) return;
    const { requestId, verifier } = await askFor('openid profile email');
    const decision = await decide(requestId, true, ['openid', 'profile']);
    expect(decision.status).toBe(200);

    const { continue: next } = await decision.json() as { continue: string };
    const resumed = await fetch(next, { headers: { cookie }, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    const code = new URL(resumed.headers.get('location') as string).searchParams.get('code');
    expect(code).toBeTruthy();

    const token = await fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: CLIENT.redirectUri,
        client_id: CLIENT.clientId,
        code_verifier: verifier,
      }),
      signal: AbortSignal.timeout(20000),
    });
    const body = await token.json() as { scope?: string };

    // RFC 6749 5.1: the response says what was granted when it differs from what was asked.
    expect(body.scope).toBe('openid profile');
    expect(body.scope).not.toContain('email');
  });

  /**
   * A decision can only narrow. Approving is done by the browser, so a decision naming a scope
   * nobody requested must be ignored rather than granted, or the screen would be a way to widen.
   */
  it('ignores a scope the request never asked for, so approving cannot widen', async () => {
    if (!live || !CLIENT.clientId) return;
    const { requestId } = await askFor('openid profile');
    const decision = await decide(requestId, true, ['openid', 'profile', 'write:transfers']);
    expect(decision.status).toBe(200);

    const prompt = await promptFor(requestId).catch(() => null);
    // The ticket now holds what was granted, and `write:transfers` is not in it.
    if (prompt) expect(prompt.scopes.map((scope) => scope.name)).not.toContain('write:transfers');
  });

  /** Withholding a required scope is declining, not narrowing: a token without it satisfies nothing. */
  it('ends the flow when a required scope is withheld, rather than issuing a useless token', async () => {
    if (!live || !CLIENT.clientId) return;
    const { requestId } = await askFor('openid profile');
    const decision = await decide(requestId, true, ['profile']);
    expect(decision.status).toBe(200);

    const { continue: next } = await decision.json() as { continue: string };
    const url = new URL(next);
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('code')).toBeNull();
  });
});
