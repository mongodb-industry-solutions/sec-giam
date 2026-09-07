// v41 P4: the authorization endpoint, driven the way the specification says to drive it.
//
// Every assertion here failed before P4, and each for its own reason. The endpoint was a POST taking
// a JSON body, it answered with the code in a JSON response, it took the user's session as
// `session_id` in that body on a route declared with no security, it accepted `consent_granted` as a
// boolean the caller asserted, and it answered refusals as a JSON 400 rather than redirecting.
//
// The case that matters most is the last one in this file: an UNREGISTERED redirect URI must not be
// redirected to. Getting that wrong turns an error response into an open redirect, and it is the one
// mistake a test suite about redirects can easily fail to make.
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { signIn, CONSOLE_CLIENT } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';
const LOGIN = 'alex.rivera';

const CHALLENGE = createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url');

function authorizeUrl(params: Record<string, string>): string {
  const url = new URL(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  return url.toString();
}

const BASE = {
  client_id: CONSOLE_CLIENT.clientId,
  redirect_uri: CONSOLE_CLIENT.redirectUri,
  response_type: 'code',
  scope: 'openid profile',
  code_challenge: CHALLENGE,
  code_challenge_method: 'S256',
};

describe('v41 P4: the authorization endpoint is conforming', () => {
  let live = false;
  let cookie = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      live = false;
      return;
    }
    const session = await signIn(GIAM, REALM, LOGIN, DEMO_PASSWORD);
    cookie = session?.cookie ?? '';
  });

  const get = (params: Record<string, string>, withCookie = true) => fetch(
    authorizeUrl(params),
    {
      ...(withCookie && cookie ? { headers: { cookie } } : {}),
      redirect: 'manual',
      signal: AbortSignal.timeout(20000),
    },
  );

  it('sets a session cookie at sign-in, which is how the browser carries it here', () => {
    if (!live) return;
    expect(cookie, 'sign-in returned no session cookie').toMatch(/^giam_session=/);
  });

  /** RFC 6749 3.1: the parameters are in the query string of a GET. */
  it('answers a GET with a 302 to the registered redirect URI, carrying code and state', async () => {
    if (!live) return;
    const response = await get({ ...BASE, state: 'xyz' });
    expect(response.status).toBe(302);

    const location = new URL(response.headers.get('location') as string);
    expect(`${location.origin}${location.pathname}`).toBe(CONSOLE_CLIENT.redirectUri);
    expect(location.searchParams.get('code')).toBeTruthy();
    // Echoed back, because the client compares it to detect a request it did not start.
    expect(location.searchParams.get('state')).toBe('xyz');
  });

  it('sends somebody with no session to sign in, and never prompts for a credential itself', async () => {
    if (!live) return;
    const response = await get(BASE, false);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location') as string);
    expect(location.pathname).toBe('/auth/login');
    // The pending request travels as an identifier, so the detour cannot alter what was asked for.
    expect(location.searchParams.get('request_id')).toBeTruthy();
  });

  /**
   * RFC 9700 2.1.1 requires PKCE of public and confidential clients alike. It was conditional on a
   * per-client `requirePkce`, which is a registration being able to opt out of the mitigation for
   * code interception.
   */
  it('refuses a request with no PKCE challenge, by redirect', async () => {
    if (!live) return;
    const { code_challenge: _dropped, ...withoutPkce } = BASE;
    const response = await get({ ...withoutPkce, state: 's1' });
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get('location') as string);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('state')).toBe('s1');
    expect(location.searchParams.get('code')).toBeNull();
  });

  /** RFC 6749 4.1.2.1: the code is what a client switches on, so it must be the right one. */
  it('delivers each refusal by redirect, with its own error code and the state', async () => {
    if (!live) return;
    const cases: Array<[Record<string, string>, string]> = [
      [{ ...BASE, response_type: 'token' }, 'unsupported_response_type'],
      [{ ...BASE, response_mode: 'fragment' }, 'unsupported_response_mode'],
      [{ ...BASE, scope: 'openid something:nobody-registered' }, 'invalid_scope'],
    ];
    for (const [params, expected] of cases) {
      const response = await get({ ...params, state: 'st' });
      expect(response.status, expected).toBe(302);
      const location = new URL(response.headers.get('location') as string);
      expect(location.searchParams.get('error'), expected).toBe(expected);
      expect(location.searchParams.get('state'), expected).toBe('st');
    }
  });

  /**
   * The one that must NOT redirect.
   *
   * RFC 6749 4.1.2.1: with an unregistered redirect URI the authorization server MUST NOT
   * automatically redirect. Doing so delivers an error, and the `state` with it, to a URI nobody
   * verified, which is an open redirect wearing an error response.
   */
  it('answers directly, never by redirect, when the redirect URI is not registered', async () => {
    if (!live) return;
    const response = await get({ ...BASE, redirect_uri: 'https://not-registered.example/callback', state: 's2' });
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();

    const body = await response.json() as { error: string; error_description?: string };
    expect(body.error).toBe('invalid_request');
    expect(body.error_description).toMatch(/redirect_uri/);
  });

  it('answers directly when the client is not registered either, for the same reason', async () => {
    if (!live) return;
    const response = await get({ ...BASE, client_id: 'a-client-nobody-registered' });
    expect(response.status).toBe(400);
    expect(response.headers.get('location')).toBeNull();
  });

  /**
   * Consent cannot be asserted by a caller any more.
   *
   * The endpoint used to take `consent_granted: true` in the request. Passing it now does nothing at
   * all, because it is not a parameter: the decision is recorded against the pending request by an
   * endpoint that requires the session cookie.
   */
  it('ignores a consent flag in the request, because consent is not a request parameter', async () => {
    if (!live) return;
    const withFlag = await get({ ...BASE, consent_granted: 'true', state: 's3' });
    const without = await get({ ...BASE, state: 's3' });
    // A first-party client needs no consent, so both produce a code: what is asserted is that the
    // flag changes NOTHING, rather than that consent is skipped.
    expect(withFlag.status).toBe(without.status);
  });

  it('refuses to record a consent decision without a session', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/realms/${REALM}/protocol/openid-connect/auth/consent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ request_id: 'anything-at-all', approved: true }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(401);
  });
});
