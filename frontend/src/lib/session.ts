'use client';

import { apiUrl } from './env';

/**
 * Turning a sign-in into a token, the same way any other client would.
 *
 * The console does not get a privileged shortcut. It is a registered public client and it runs the
 * authorization code flow with PKCE like the merchant does, because a console with its own private
 * path to a token is a second authentication mechanism, and a second mechanism is the one that ends
 * up without the checks the first one has.
 *
 * Held in session storage rather than a cookie: nothing here should ride along automatically on
 * every request the browser happens to make to this origin.
 */

export const CONSOLE_CLIENT_ID = 'giam-console';
const TOKEN_KEY = 'giam.access.token';
const SESSION_KEY = 'giam.session.id';

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: base64url(new Uint8Array(digest)) };
}

export function storedToken(): string {
  return typeof window === 'undefined' ? '' : window.sessionStorage.getItem(TOKEN_KEY) ?? '';
}

export function storedSessionId(): string {
  return typeof window === 'undefined' ? '' : window.sessionStorage.getItem(SESSION_KEY) ?? '';
}

export function clearSession(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(SESSION_KEY);
}

/**
 * Exchanges an established session for an access token.
 *
 * Returns null rather than throwing when it cannot: a sign-in that succeeded should not be reported
 * as a failure because the console could not immediately obtain a token for itself. The person is
 * signed in; what they lose is the screens that need a token, and those say so on their own.
 */
export async function tokenFromSession(realm: string, sessionId: string): Promise<string | null> {
  window.sessionStorage.setItem(SESSION_KEY, sessionId);
  const redirectUri = `${window.location.origin}/auth/callback`;

  try {
    const { verifier, challenge } = await pkce();

    const authorize = await fetch(apiUrl(`/realms/${realm}/protocol/openid-connect/auth`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_id: CONSOLE_CLIENT_ID,
        redirect_uri: redirectUri,
        response_type: 'code',
        session_id: sessionId,
        scope: 'openid profile email',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      }),
    });
    if (!authorize.ok) return null;
    const { code } = await authorize.json();

    const token = await fetch(apiUrl(`/realms/${realm}/protocol/openid-connect/token`), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: CONSOLE_CLIENT_ID,
        code_verifier: verifier,
      }),
    });
    if (!token.ok) return null;

    const { access_token: accessToken } = await token.json();
    if (accessToken) window.sessionStorage.setItem(TOKEN_KEY, accessToken);
    return accessToken ?? null;
  } catch {
    return null;
  }
}
