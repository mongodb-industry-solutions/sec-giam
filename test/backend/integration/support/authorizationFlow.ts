import { createHash, randomBytes } from 'crypto';

/**
 * The authorization code flow, driven the way a conforming client drives it.
 *
 * One helper because three suites were each doing it, and each had memorised the shape the endpoint
 * used to have: a POST with a JSON body carrying `session_id`, a JSON response holding the code, and
 * a second POST repeating the whole request with `consent_granted: true`. When v41 P4 made the
 * endpoint conforming, all three broke in the same way for the same reason, which is what a shared
 * helper exists to prevent.
 *
 * What it exercises is deliberately the real thing rather than a shortcut: the session arrives as a
 * COOKIE, the authorization endpoint is a `GET`, and the code is read out of the `Location` header
 * of a 302. A test that took a shortcut past any of those would pass while the flow was broken for
 * every browser.
 */

export const CONSOLE_CLIENT = {
  clientId: 'giam-console',
  redirectUri: 'http://localhost:8086/auth/callback',
};

const TIMEOUT = 20000;

/** The session cookie a sign-in hands back, ready to be sent on the next request. */
export function sessionCookieFrom(response: Response): string | undefined {
  const header = response.headers.get('set-cookie');
  if (!header) return undefined;
  const match = /giam_session=([^;]+)/.exec(header);
  return match ? `giam_session=${match[1]}` : undefined;
}

export interface SignedInSession {
  sessionId: string;
  cookie: string;
  subjectId: string;
}

/** Signs in and keeps both halves: the id for anything that names a session, the cookie for the flow. */
export async function signIn(giam: string, realm: string, login: string, password: string): Promise<SignedInSession | null> {
  const response = await fetch(`${giam}/realms/${realm}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login, password }),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  if (!response.ok) return null;
  const cookie = sessionCookieFrom(response);
  if (!cookie) return null;
  const body = await response.json() as { sessionId: string; subjectId: string };
  return { sessionId: body.sessionId, cookie, subjectId: body.subjectId };
}

/**
 * Runs the flow and returns the access token, or '' when any step refuses.
 *
 * Returns the empty string rather than throwing so a suite can assert "this persona could not sign
 * in" as a value, which is what the console authorization suite is about.
 */
export async function tokenFor(
  giam: string,
  realm: string,
  login: string,
  password: string,
  options: { scope?: string; client?: typeof CONSOLE_CLIENT } = {},
): Promise<string> {
  const client = options.client ?? CONSOLE_CLIENT;
  const scope = options.scope ?? 'openid profile email';

  const session = await signIn(giam, realm, login, password);
  if (!session) return '';

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const url = new URL(`${giam}/realms/${realm}/protocol/openid-connect/auth`);
  url.searchParams.set('client_id', client.clientId);
  url.searchParams.set('redirect_uri', client.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scope);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  const authorize = await fetch(url, {
    headers: { cookie: session.cookie },
    // Manual, because the redirect IS the answer: following it would fetch the console's callback
    // page and lose the code that is in the Location header.
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const location = authorize.headers.get('location');
  if (!location) return '';

  const code = new URL(location).searchParams.get('code');
  // A redirect carrying `error` instead of `code` is a refusal delivered the way the specification
  // says to deliver one, so it is not an exception here either.
  if (!code) return '';

  const token = await fetch(`${giam}/realms/${realm}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: client.redirectUri,
      client_id: client.clientId,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  if (!token.ok) return '';
  const body = await token.json() as { access_token?: string };
  return body.access_token ?? '';
}
