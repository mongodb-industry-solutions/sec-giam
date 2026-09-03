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
// The realm that signed the token, and the realm the console is currently acting on. They are the
// same for everybody who administers one realm, and the pair is the only thing that changes when
// somebody switches: no second token, no second sign-in, no second identity.
const REALM_KEY = 'giam.realm';
const ACTIVE_REALM_KEY = 'giam.realm.active';

/** Fired when the acting realm changes, so every mounted screen reloads against the new one. */
export const REALM_CHANGED_EVENT = 'giam:realm-changed';
/**
 * Fired when a session begins or ends.
 *
 * The console shell reads the session to decide whether to frame the page at all, and signing in
 * happens on a screen INSIDE that shell without the address changing. Without this the shell keeps
 * the answer it computed while nobody was signed in, and the header and the sidebar stay missing
 * until the page is reloaded by hand.
 */
export const SESSION_CHANGED_EVENT = 'giam:session-changed';
// Profile claims read from the UserInfo endpoint, kept beside the token they were read with.
export const PROFILE_KEY = 'giam.userinfo';
/**
 * The name the sign-in itself returned.
 *
 * Kept because the console otherwise has NO synchronous source for it. An access token carries no
 * profile claims by design (RFC 9068 keeps them out: the token is addressed to a resource server,
 * not to whoever it describes), and this console stores no id token. So without this the only way
 * to learn a name is the UserInfo round trip, and every screen showed a raw subject id until it
 * came back, or forever if it failed.
 *
 * The sign-in response already carried it and it was being thrown away.
 */
const NAME_KEY = 'giam.userName';

// The realm every console call is addressed to. Remembered at sign-in rather than guessed per page,
// because a page that guesses wrong reads somebody else's realm or nothing at all.
export const DEFAULT_REALM = 'leafypay';

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

/** The name this session signed in as. Empty when unknown, never a subject id. */
export function storedUserName(): string {
  return typeof window === 'undefined' ? '' : window.sessionStorage.getItem(NAME_KEY) ?? '';
}

export function rememberUserName(userName: string): void {
  if (typeof window === 'undefined' || !userName) return;
  window.sessionStorage.setItem(NAME_KEY, userName);
}

/** The realm that authenticated this person and issued their token. Never changes while signed in. */
export function storedHomeRealm(): string {
  if (typeof window === 'undefined') return DEFAULT_REALM;
  return window.sessionStorage.getItem(REALM_KEY) || DEFAULT_REALM;
}

/**
 * The realm every console call is addressed to.
 *
 * The home realm unless the person has switched to one they hold a grant over. The switch changes
 * the realm in the path and nothing else: the same token is presented, the authority verifies it
 * against the realm that signed it, and the grant is what decides whether the request is allowed.
 */
export function storedRealm(): string {
  if (typeof window === 'undefined') return DEFAULT_REALM;
  return window.sessionStorage.getItem(ACTIVE_REALM_KEY) || storedHomeRealm();
}

export function isCrossRealm(): boolean {
  return storedRealm() !== storedHomeRealm();
}

/** Persists the choice and tells every mounted screen to read its realm again. */
export function setActiveRealm(name: string): void {
  if (typeof window === 'undefined') return;
  window.sessionStorage.setItem(ACTIVE_REALM_KEY, name);
  window.dispatchEvent(new CustomEvent(REALM_CHANGED_EVENT, { detail: name }));
}

export function clearSession(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(SESSION_KEY);
  window.sessionStorage.removeItem(REALM_KEY);
  window.sessionStorage.removeItem(ACTIVE_REALM_KEY);
  window.sessionStorage.removeItem(PROFILE_KEY);
  window.sessionStorage.removeItem(NAME_KEY);
  announceSessionChange();
}

/** Announced from here, the one place a token is written or removed, so no caller can forget. */
export function announceSessionChange(): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent(SESSION_CHANGED_EVENT));
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
  window.sessionStorage.setItem(REALM_KEY, realm);
  // A fresh sign-in acts on the realm that authenticated it. Inheriting a realm chosen in an earlier
  // session would put somebody somewhere they did not ask to be.
  window.sessionStorage.setItem(ACTIVE_REALM_KEY, realm);
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
    if (accessToken) {
      window.sessionStorage.setItem(TOKEN_KEY, accessToken);
      announceSessionChange();
    }
    return accessToken ?? null;
  } catch {
    return null;
  }
}
