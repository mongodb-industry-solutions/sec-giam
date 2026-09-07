'use client';

import { apiUrl, apiUrlObject } from './env';

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
// The caller's own effective permissions, read fresh from the authority because the token itself
// carries roles rather than entitlements by default (P9) and is therefore not enough to gate the UI.
export const PERMISSIONS_KEY = 'giam.permissions';
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
// The PKCE verifier and the redirect it was minted for, held across the navigation the
// authorization endpoint answers with. This tab, this attempt, and no longer.
const VERIFIER_KEY = 'giam.pkceVerifier';
const REDIRECT_KEY = 'giam.redirectUri';

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

/** The name to greet somebody by, not their login. Kept for the first paint, before UserInfo. */
export function rememberUserName(displayName: string): void {
  if (typeof window === 'undefined' || !displayName) return;
  window.sessionStorage.setItem(NAME_KEY, displayName);
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
  // What the caller may do is a property of the realm being acted on, not just of the token, so a
  // cached answer from the realm just left would be wrong here rather than merely stale.
  window.sessionStorage.removeItem(PERMISSIONS_KEY);
  window.dispatchEvent(new CustomEvent(REALM_CHANGED_EVENT, { detail: name }));
}

export function clearSession(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
  window.sessionStorage.removeItem(SESSION_KEY);
  window.sessionStorage.removeItem(REALM_KEY);
  window.sessionStorage.removeItem(ACTIVE_REALM_KEY);
  window.sessionStorage.removeItem(PROFILE_KEY);
  window.sessionStorage.removeItem(PERMISSIONS_KEY);
  window.sessionStorage.removeItem(NAME_KEY);
  announceSessionChange();
}

/** Announced from here, the one place a token is written or removed, so no caller can forget. */
export function announceSessionChange(): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent(SESSION_CHANGED_EVENT));
}

/**
 * Starts the console's own authorization flow, by NAVIGATING.
 *
 * It used to POST to the authorization endpoint, read the code out of a JSON response and exchange
 * it in the background. That worked only because the endpoint was not a conforming one: since v41 P4
 * the authorization endpoint is a `GET` that answers with a 302, which is what every other client
 * gets and what makes the console an ordinary client of this authority rather than a special case.
 *
 * So the browser goes there. The session travels as a COOKIE, the authority answers with a redirect
 * to `/auth/callback` carrying the code, and the callback exchanges it. This does not return: the
 * page is leaving.
 *
 * The verifier is kept in session storage because the exchange happens after the navigation, in a
 * different page load. Session storage rather than local storage: it belongs to this tab and to this
 * attempt, and outliving either would leave a verifier lying around for a flow nobody is completing.
 */
export async function startConsoleAuthorization(realm: string, sessionId: string): Promise<void> {
  window.sessionStorage.setItem(SESSION_KEY, sessionId);
  window.sessionStorage.setItem(REALM_KEY, realm);
  // A fresh sign-in acts on the realm that authenticated it. Inheriting a realm chosen in an earlier
  // session would put somebody somewhere they did not ask to be.
  window.sessionStorage.setItem(ACTIVE_REALM_KEY, realm);

  const redirectUri = `${window.location.origin}/auth/callback`;
  const { verifier, challenge } = await pkce();
  window.sessionStorage.setItem(VERIFIER_KEY, verifier);
  window.sessionStorage.setItem(REDIRECT_KEY, redirectUri);

  const url = apiUrlObject(`/realms/${realm}/protocol/openid-connect/auth`);
  url.searchParams.set('client_id', CONSOLE_CLIENT_ID);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  window.location.assign(url.toString());
}

/**
 * Completes it, from the callback page.
 *
 * Returns null rather than throwing: a sign-in that succeeded should not be reported as a failure
 * because the console could not obtain a token for itself. The person IS signed in; what they lose
 * is the screens that need a token, and those say so on their own.
 */
export async function completeConsoleAuthorization(code: string): Promise<string | null> {
  const realm = window.sessionStorage.getItem(REALM_KEY) ?? '';
  const verifier = window.sessionStorage.getItem(VERIFIER_KEY) ?? '';
  const redirectUri = window.sessionStorage.getItem(REDIRECT_KEY) ?? `${window.location.origin}/auth/callback`;
  // Single use, and removed before the exchange rather than after: a verifier left behind is one a
  // second attempt could pick up.
  window.sessionStorage.removeItem(VERIFIER_KEY);
  if (!realm || !verifier) return null;

  try {
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
