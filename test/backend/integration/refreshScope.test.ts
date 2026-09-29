/**
 * `grant_type=refresh_token` carries the ORIGINAL grant's scope forward when the request omits its
 * own `scope` parameter, exactly as RFC 6749 §6 describes ("if omitted, is treated as equal to the
 * scope originally granted").
 *
 * THE DEFECT THIS FIXES. The refresh branch read `body.scope` directly. An ordinary client that
 * follows the RFC and does not repeat its scope on refresh (this realm's own merchant app among
 * them) got `''.split(' ').filter(Boolean)`, an EMPTY array, so every refreshed token carried no
 * scope at all: a session that worked right after login started failing every call with
 * `insufficient_scope` the moment its access token first expired. Reproduced against the real
 * Espresso Works merchant client and the real Luis Fernandez persona this demo already seeds.
 */
import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { clientSecretFor } from '@leafypay/platform-links';
import { signIn } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'LeafyIdp';
const LOGIN = 'luis.fernandez';
const PASSWORD = 'demo-password';

const MERCHANT_CLIENT = {
  clientId: 'oauth001-0000-4000-8000-000000000001',
  redirectUri: 'http://localhost:8082/api/auth/callback',
};
const MERCHANT_SECRET = clientSecretFor(MERCHANT_CLIENT.clientId);
// Exactly what merchant/src/lib/oauth.ts basicAuthHeader() sends: this is a confidential client, and
// while PKCE alone vouches for the authorization_code exchange, a refresh has no PKCE artifact to
// check and falls back to ordinary client authentication.
const BASIC_AUTH = `Basic ${Buffer.from(`${MERCHANT_CLIENT.clientId}:${MERCHANT_SECRET}`).toString('base64')}`;

// What the merchant app actually asks for (merchant/src/lib/env.ts REQUESTED_SCOPES).
const REQUESTED_SCOPE = 'openid profile read:beneficiaries write:beneficiaries read:transactions '
  + 'read:accounts read:merchant_profile read:notifications write:transfers read:rtp write:rtp';

/** The full authorization_code exchange, returning the raw token response (not just access_token). */
async function exchangeForTokens(): Promise<Record<string, unknown> | null> {
  const session = await signIn(GIAM, REALM, LOGIN, PASSWORD);
  if (!session) return null;

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const authorizeUrl = new URL(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/auth`);
  authorizeUrl.searchParams.set('client_id', MERCHANT_CLIENT.clientId);
  authorizeUrl.searchParams.set('redirect_uri', MERCHANT_CLIENT.redirectUri);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', REQUESTED_SCOPE);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');

  let response = await fetch(authorizeUrl, {
    headers: { cookie: session.cookie },
    redirect: 'manual',
    signal: AbortSignal.timeout(20000),
  });
  let location = response.headers.get('location');
  if (!location) return null;

  // First-time authorization for this persona+client combination in a fresh test run: consent.
  if (location.includes('/auth/consent')) {
    const requestId = new URL(location).searchParams.get('request_id');
    if (!requestId) return null;
    const decided = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/auth/consent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: session.cookie },
      body: JSON.stringify({ request_id: requestId, approved: true }),
      signal: AbortSignal.timeout(20000),
    });
    if (!decided.ok) return null;
    const { continue: next } = await decided.json() as { continue: string };
    response = await fetch(next, { headers: { cookie: session.cookie }, redirect: 'manual', signal: AbortSignal.timeout(20000) });
    location = response.headers.get('location');
    if (!location) return null;
  }

  const code = new URL(location).searchParams.get('code');
  if (!code) return null;

  const tokenResponse = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: MERCHANT_CLIENT.redirectUri,
      client_id: MERCHANT_CLIENT.clientId,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!tokenResponse.ok) return null;
  return tokenResponse.json() as Promise<Record<string, unknown>>;
}

describe('refresh_token grant preserves the original scope', () => {
  it('a full login carries the requested scope, so the refresh check below is not vacuous', async () => {
    const tokens = await exchangeForTokens();
    expect(tokens, 'authorization_code exchange failed; is GIAM running and seeded?').not.toBeNull();
    const scope = String(tokens?.scope ?? '').split(' ');
    for (const expected of ['read:beneficiaries', 'read:accounts', 'read:transactions']) {
      expect(scope, `initial token scope: "${tokens?.scope}"`).toContain(expected);
    }
  });

  it('THE DEFECT: a refresh call that omits scope (the RFC-compliant, common case) keeps it', async () => {
    const tokens = await exchangeForTokens();
    expect(tokens).not.toBeNull();
    const refreshToken = tokens?.refresh_token as string | undefined;
    expect(refreshToken, 'no refresh_token in the token response').toBeTruthy();

    // Exactly what merchant/src/lib/oauth.ts refreshTokens() sends: no `scope` parameter at all.
    const refreshed = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC_AUTH },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken!,
        client_id: MERCHANT_CLIENT.clientId,
      }),
      signal: AbortSignal.timeout(20000),
    });
    const refreshedText = await refreshed.text();
    expect(refreshed.status, refreshedText).toBe(200);
    const refreshedBody = JSON.parse(refreshedText) as { scope?: string; access_token?: string };
    const refreshedScope = String(refreshedBody.scope ?? '').split(' ').filter(Boolean);

    // Before the fix this was []: every one of these assertions failed.
    expect(refreshedScope.length, `refreshed token scope: "${refreshedBody.scope}"`).toBeGreaterThan(0);
    for (const expected of ['read:beneficiaries', 'read:accounts', 'read:transactions']) {
      expect(refreshedScope, `refreshed token scope: "${refreshedBody.scope}"`).toContain(expected);
    }
  });

  it('a refresh MAY narrow the scope, exactly as RFC 6749 §6 allows', async () => {
    const tokens = await exchangeForTokens();
    const refreshToken = tokens?.refresh_token as string | undefined;
    expect(refreshToken).toBeTruthy();

    const refreshed = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC_AUTH },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken!,
        client_id: MERCHANT_CLIENT.clientId,
        scope: 'openid read:accounts',
      }),
      signal: AbortSignal.timeout(20000),
    });
    const refreshedText2 = await refreshed.text();
    expect(refreshed.status, refreshedText2).toBe(200);
    const body = JSON.parse(refreshedText2) as { scope?: string };
    expect(body.scope).toBe('openid read:accounts');
  });

  it('a refresh MUST NOT widen beyond what was granted', async () => {
    const tokens = await exchangeForTokens();
    const refreshToken = tokens?.refresh_token as string | undefined;
    expect(refreshToken).toBeTruthy();

    const refreshed = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC_AUTH },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken!,
        client_id: MERCHANT_CLIENT.clientId,
        // Never granted to this client at all: not in its own registration.
        scope: 'openid write:payments_super_admin',
      }),
      signal: AbortSignal.timeout(20000),
    });
    const refreshedText3 = await refreshed.text();
    expect(refreshed.status, refreshedText3).toBe(400);
    const body = JSON.parse(refreshedText3) as { error?: string };
    expect(body.error).toBe('invalid_scope');
  });

  it('a refused scope leaves the presented token usable, so a corrected retry is not read as theft', async () => {
    const tokens = await exchangeForTokens();
    const refreshToken = tokens?.refresh_token as string | undefined;
    expect(refreshToken).toBeTruthy();

    const refused = await refresh(refreshToken!, 'openid write:payments_super_admin');
    expect(refused.status).toBe(400);

    // Before the fix the token had already been rotated, so this retry hit reuse detection and the
    // whole session was deleted.
    const retried = await refresh(refreshToken!);
    const retriedText = await retried.text();
    expect(retried.status, retriedText).toBe(200);
  });

  it('the refresh token carries its own scope, and a narrowed refresh does not shrink the next one', async () => {
    const tokens = await exchangeForTokens();
    const original = String(tokens?.scope ?? '').split(' ').filter(Boolean).sort();
    const refreshToken = tokens?.refresh_token as string;
    expect(claimsOf(refreshToken).scope?.split(' ').sort()).toEqual(original);

    const narrowed = await refresh(refreshToken, 'openid read:accounts');
    const narrowedBody = await narrowed.json() as { scope?: string; refresh_token?: string };
    expect(narrowedBody.scope).toBe('openid read:accounts');

    // RFC 6749 section 6: the new refresh token's scope is identical to the one presented.
    const next = await refresh(narrowedBody.refresh_token!);
    const nextBody = await next.json() as { scope?: string };
    expect(String(nextBody.scope ?? '').split(' ').filter(Boolean).sort()).toEqual(original);
  });

  it('a replayed token with a refused scope is still caught as reuse, and ends the session', async () => {
    const tokens = await exchangeForTokens();
    const first = tokens?.refresh_token as string;
    const rotated = await refresh(first);
    expect(rotated.status).toBe(200);
    const { refresh_token: current } = await rotated.json() as { refresh_token: string };

    // The already-rotated token, with a scope beyond the grant: invalid_scope here would hide theft.
    const replayed = await refresh(first, 'openid write:payments_super_admin');
    const replayedBody = await replayed.json() as { error?: string; error_description?: string };
    expect(replayed.status).toBe(400);
    expect(replayedBody.error).toBe('invalid_grant');
    expect(replayedBody.error_description).toMatch(/already been used/);

    // The session is gone, so even the current token no longer refreshes.
    const after = await refresh(current);
    expect(after.status).toBe(400);
  });
});

/** One refresh call, as the merchant app makes it. */
function refresh(refreshToken: string, scope?: string): Promise<Response> {
  return fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC_AUTH },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: MERCHANT_CLIENT.clientId,
      ...(scope ? { scope } : {}),
    }),
    signal: AbortSignal.timeout(20000),
  });
}

function claimsOf(jwt: string): { scope?: string } {
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
}
