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
  const response = await fetch(`${giam}/api/v1/realms/${realm}/login`, {
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
export interface IssuedToken {
  token: string;
  /** The session the sign-in opened, so a suite can close what it opened. */
  sessionId: string;
}

/**
 * The flow, reporting BOTH halves: the token and the session behind it.
 *
 * `tokenFor` discarded the session id, which meant every suite that signed a persona in left a live
 * session behind for the length of its idle window. A few runs of the whole suite put a hundred real
 * sessions into the demo, all of them correct records of something nobody was using, and the
 * sessions screen then looked broken when it was in fact honest. Use this and `endSession` together.
 */
export async function issueTokenFor(
  giam: string,
  realm: string,
  login: string,
  password: string,
  options: { scope?: string; client?: typeof CONSOLE_CLIENT } = {},
): Promise<IssuedToken> {
  const client = options.client ?? CONSOLE_CLIENT;
  const scope = options.scope ?? 'openid profile email';

  const session = await signIn(giam, realm, login, password);
  if (!session) return { token: '', sessionId: '' };

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');

  const url = new URL(`${giam}/api/v1/realms/${realm}/protocol/oidc/auth`);
  url.searchParams.set('client_id', client.clientId);
  url.searchParams.set('redirect_uri', client.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', scope);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');

  const authorize = async () => fetch(url, {
    headers: { cookie: session.cookie },
    // Manual, because the redirect IS the answer: following it would fetch the console's callback
    // page and lose the code that is in the Location header.
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT),
  });

  const nothing = { token: '', sessionId: session.sessionId };
  let location = (await authorize()).headers.get('location');
  if (!location) return nothing;

  /**
   * ANSWER THE CONSENT QUESTION when the authority asks it.
   *
   * A client that is not first party needs the person's approval before a code exists, and since
   * v41 P5 that approval is recorded by the authority against the pending request rather than
   * asserted in the authorization call. The flow therefore redirects to the consent page, and a
   * helper that stopped at the first redirect would report "could not sign in" for every
   * third-party client on a freshly seeded directory.
   *
   * The previous helper handled this too, in the shape the endpoint used to have. Dropping it when
   * the endpoint became conforming left the same gap in a new form: this suite passed only for
   * whoever already had a grant, which is the exact defect an earlier comment in it complained
   * about.
   */
  if (location.includes('/auth/consent')) {
    const requestId = new URL(location).searchParams.get('request_id');
    if (!requestId) return nothing;

    const decided = await fetch(`${giam}/api/v1/realms/${realm}/protocol/oidc/auth/consent`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: session.cookie },
      // No `granted_scopes`, which means all of them: this helper exists to obtain a working token,
      // and partial consent is asserted where it belongs, in `partialConsent.test.ts`.
      body: JSON.stringify({ request_id: requestId, approved: true }),
      signal: AbortSignal.timeout(TIMEOUT),
    });
    if (!decided.ok) return nothing;

    const { continue: next } = await decided.json() as { continue: string };
    const resumed = await fetch(next, {
      headers: { cookie: session.cookie }, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT),
    });
    location = resumed.headers.get('location');
    if (!location) return nothing;
  }

  const code = new URL(location).searchParams.get('code');
  // A redirect carrying `error` instead of `code` is a refusal delivered the way the specification
  // says to deliver one, so it is not an exception here either.
  if (!code) return nothing;

  const token = await fetch(`${giam}/api/v1/realms/${realm}/protocol/oidc/token`, {
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
  if (!token.ok) return nothing;
  const body = await token.json() as { access_token?: string };
  return { token: body.access_token ?? '', sessionId: session.sessionId };
}

/**
 * The token alone, for the suites that do not care which session carried it.
 *
 * Kept so every existing caller stays as it is, and deliberately NOT the place to add cleanup: a
 * helper that signed out behind the caller would break any suite that goes on to use the token.
 */
export async function tokenFor(
  giam: string,
  realm: string,
  login: string,
  password: string,
  options: { scope?: string; client?: typeof CONSOLE_CLIENT } = {},
): Promise<string> {
  return (await issueTokenFor(giam, realm, login, password, options)).token;
}

/**
 * Ends a session a suite opened, through the same endpoint the console uses.
 *
 * Best effort by design: a test that has already asserted what it came for should not fail in
 * teardown because the thing it was cleaning up had lapsed on its own.
 */
export async function endSession(
  giam: string,
  realm: string,
  token: string,
  sessionId: string,
): Promise<void> {
  if (!token || !sessionId) return;
  try {
    await fetch(`${giam}/api/v1/realms/${realm}/sessions/${encodeURIComponent(sessionId)}`, {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(TIMEOUT),
    });
  } catch {
    // Nothing to do: the session is gone either way, which is the outcome this wanted.
  }
}
