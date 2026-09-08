'use client';

import { apiUrl } from './env';
import {
  PERMISSIONS_KEY, PROFILE_KEY, REALM_CHANGED_EVENT, storedHomeRealm, storedRealm, storedToken, storedUserName,
} from './session';

/**
 * What the console knows about the signed-in principal, and how it talks to the authority.
 *
 * Claims are read here only to decide what to RENDER. Every decision that matters is made by the API
 * against the same token, and it checks the signature. A screen that a claim would hide is still
 * refused by the API when somebody types the address, which is the order these two checks belong in.
 */

export interface Claims {
  sub: string;
  preferred_username?: string;
  name?: string;
  email?: string;
  roles?: string[];
  /**
   * Realms this principal may administer besides the issuing one, by NAME.
   *
   * It was `[{id, name}]` until v41 P1. Nothing here read the id: the switcher calls
   * `/administrable-realms`, which answers with the realm record and the permissions actually held
   * there, because a switcher showing only names would hide that a grant is usually narrower away
   * from home. So the id was two UUIDs per realm in every administrator's token, serving nobody.
   */
  admin_realms?: string[];
  scope?: string;
  /**
   * Fine-grained authority, when the client asked to narrow. `entitlements` per RFC 9068 2.2.3.1,
   * as `resource:action` STRINGS. This was typed as the v39 `{resource, action}` objects under the
   * name `permissions`, which had been wrong on both counts since v40.
   */
  entitlements?: string[];
  exp?: number;
  iat?: number;
  iss?: string;
  aud?: string | string[];
  /** The client that obtained this token, and the session it was obtained under. */
  client_id?: string;
  sid?: string;
  jti?: string;
}

/**
 * What the authority is willing to say about the subject, from the UserInfo endpoint.
 *
 * The access token deliberately carries none of this: it says what the holder may do, not who they
 * are. Profile claims are asked for separately, and only the granted scopes decide what comes back,
 * so an absent field here means "not granted" rather than "not known".
 */
export interface UserInfo {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  [claim: string]: unknown;
}

export function decodeClaims(token: string): Claims | null {
  const segments = token.split('.');
  if (segments.length !== 3) return null;
  try {
    return JSON.parse(atob(segments[1].replace(/-/g, '+').replace(/_/g, '/'))) as Claims;
  } catch {
    return null;
  }
}

/** The claims of the token currently held, or null when nobody is signed in. */
export function currentClaims(): Claims | null {
  const token = storedToken();
  return token ? decodeClaims(token) : null;
}

export function isExpired(claims: Claims): boolean {
  return typeof claims.exp === 'number' && claims.exp * 1000 <= Date.now();
}

// Kept in memory so a navigation costs nothing, and in session storage so a reload does not either.
let profileCache: UserInfo | null = null;
let profileInFlight: Promise<UserInfo | null> | null = null;

export function cachedUserInfo(): UserInfo | null {
  if (profileCache) return profileCache;
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(PROFILE_KEY);
    profileCache = raw ? JSON.parse(raw) as UserInfo : null;
  } catch {
    profileCache = null;
  }
  return profileCache;
}

/**
 * Reads the subject's profile once per session.
 *
 * Returns null rather than throwing when it cannot be read: a console that cannot learn somebody's
 * name still works, and every screen here falls back to the subject the token names.
 */
export async function loadUserInfo(): Promise<UserInfo | null> {
  const claims = currentClaims();
  if (!claims) return null;

  const cached = cachedUserInfo();
  if (cached && cached.sub === claims.sub) return cached;

  // Always the HOME realm, never the acting one: the profile belongs to the realm that issued the
  // token, so asking a realm being administered would present a token it does not accept.
  profileInFlight ??= callApi<UserInfo>('/protocol/openid-connect/userinfo', {
    subject: 'your profile',
    realm: storedHomeRealm(),
  })
    .then((info) => {
      profileCache = info;
      try { window.sessionStorage.setItem(PROFILE_KEY, JSON.stringify(info)); } catch {}
      return info;
    })
    .catch((err) => {
      // Degrading to the subject id is deliberate, but degrading silently is not: without this the
      // screen shows an identifier and nothing says why.
      console.warn('[console] profile unavailable, showing the subject id instead:', err);
      return null;
    })
    .finally(() => { profileInFlight = null; });

  return profileInFlight;
}

export interface MyPermissions {
  permissions: string[];
  roles: string[];
  scopeKind: 'self' | 'all';
}

// Kept beside the profile cache, and invalidated the same two ways: signing out, and switching the
// realm being acted on, because the answer is a property of that realm, not just of the token.
let permissionsCache: MyPermissions | null = null;
let permissionsInFlight: Promise<MyPermissions | null> | null = null;

// `setActiveRealm` clears the storage half; this clears the in-memory half, so a switch cannot leave
// the module holding the previous realm's answer after the storage key it was read from is gone.
if (typeof window !== 'undefined') {
  window.addEventListener(REALM_CHANGED_EVENT, () => { permissionsCache = null; });
}

export function cachedPermissions(): MyPermissions | null {
  if (permissionsCache) return permissionsCache;
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.sessionStorage.getItem(PERMISSIONS_KEY);
    permissionsCache = raw ? JSON.parse(raw) as MyPermissions : null;
  } catch {
    permissionsCache = null;
  }
  return permissionsCache;
}

/**
 * Reads the caller's own effective permissions once per realm.
 *
 * The access token carries roles rather than entitlements by default (P9), so `can()` cannot decide
 * what to render from the token alone without being wrong on every ordinary login: the entitlements
 * claim is populated only when a client deliberately narrows, which the console itself never does.
 * This asks the authority the same question it asks itself when it decides, so the answer is never
 * stale about a role withdrawn a moment ago the way a claim baked into a token would be.
 */
export async function loadPermissions(): Promise<MyPermissions | null> {
  if (!currentClaims()) return null;

  const cached = cachedPermissions();
  if (cached) return cached;

  permissionsInFlight ??= callApi<MyPermissions>('/me/permissions', { subject: 'your permissions' })
    .then((info) => {
      permissionsCache = info;
      try { window.sessionStorage.setItem(PERMISSIONS_KEY, JSON.stringify(info)); } catch {}
      return info;
    })
    .catch((err) => {
      // Degrading to "nothing granted" is deliberate: a console that cannot ask still works, it just
      // shows less rather than guessing.
      console.warn('[console] effective permissions unavailable, gated screens stay hidden:', err);
      return null;
    })
    .finally(() => { permissionsInFlight = null; });

  return permissionsInFlight;
}

/**
 * The friendliest name the console can put on screen for this principal.
 *
 * The profile is preferred when it has been read and belongs to the same subject; the token alone
 * only ever yields the subject id, which is an identifier, not a name.
 */
export function displayName(claims: Claims): string {
  const info = cachedUserInfo();
  const fromProfile = info && info.sub === claims.sub ? info.name || info.preferred_username : '';
  /**
   * A NAME, and never a subject id.
   *
   * The subject used to be the last resort here, and it was reached constantly: v40 slimmed the
   * access token to the claims that carry authority, so `name` and `preferred_username` are simply
   * not in it, and the profile read is asynchronous. Every header and menu therefore rendered
   * `a1000070-0000-4000-8000-000000000070` on first paint, and permanently whenever UserInfo failed.
   *
   * An opaque identifier is not a name. It tells the person nothing they did not know, it is
   * unreadable at a glance, and it is the wrong thing to put where somebody looks to confirm who
   * they are signed in as. The identifier still matters, so it is shown on the profile screen where
   * that level of detail belongs, and never as a substitute for a name.
   */
  return fromProfile
    || claims.name
    || claims.preferred_username
    || storedUserName()
    || 'Your account';
}

export function initials(claims: Claims): string {
  const source = displayName(claims).trim();
  const parts = source.split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/**
 * Whether this principal holds a permission, for deciding what to render.
 *
 * The token's `entitlements` claim is checked first, for a client that deliberately narrowed. The
 * console never does, so this falls back to the effective permissions read fresh from the authority
 * (`loadPermissions`): without the fallback, every default login carries roles only and this would
 * answer "no" for everybody, hiding controls the API would in fact allow.
 */
export function can(claims: Claims | null, resource: string, action: string): boolean {
  if (!claims) return false;
  const wanted = `${resource}:${action}`;
  if ((claims.entitlements ?? []).includes(wanted)) return true;
  return (cachedPermissions()?.permissions ?? []).includes(wanted);
}

// Offered only when the claims say the person administers identity, so the console never advertises
// a surface that would refuse them.
export function administersIdentity(claims: Claims | null): boolean {
  if (!claims) return false;
  if ((claims.roles ?? []).some((role) => /admin|auditor|security/i.test(role))) return true;
  const granted = [...(claims.entitlements ?? []), ...(cachedPermissions()?.permissions ?? [])];
  return granted.some((entitlement) => /realm|client|identit|role|polic|key|session|audit/i.test(entitlement));
}

/** A failure a screen can print as it is, rather than a stack trace or a bare status code. */
export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function messageFor(status: number, detail: string, subject: string): string {
  if (status === 401) return 'That session is not valid any more. Sign in again.';
  if (status === 403) return `Your roles do not allow reading ${subject}.`;
  if (status === 404) return `${subject} could not be found.`;
  if (status >= 500) return `The identity service failed while reading ${subject}.`;
  return detail || `${subject} could not be loaded.`;
}

interface CallOptions {
  method?: string;
  body?: unknown;
  /** Plain-language name of what is being read, used to build the error message. */
  subject?: string;
  query?: Record<string, string | number | undefined>;
  /**
   * Address the call at a named realm instead of the one currently selected.
   *
   * Used only by the few reads that must not follow the switcher, such as asking which realms the
   * person may switch TO: a grant withdrawn while it was selected would otherwise make the question
   * unanswerable exactly when it needs answering.
   */
  realm?: string;
  /**
   * Skips the `/realms/{realm}` prefix entirely.
   *
   * For the handful of routes that act ON a realm rather than inside one (`/realms`,
   * `/realms/:realm` themselves): those are never reached "as the realm currently selected", they
   * are the thing being administered, so nesting them under the switcher's realm would ask for a
   * path that does not exist. `path` must then start with `/realms` itself when that is what is
   * meant, since nothing prepends it here.
   */
  topLevel?: boolean;
}

/**
 * One call to the authority, addressed to the realm the person signed into.
 *
 * Path is written without the realm prefix so no caller has to remember to add it, and so a page
 * cannot accidentally read a realm the person is not in. `topLevel` is the one deliberate escape
 * from that rule, for the routes that administer a realm itself rather than something inside one.
 */
export async function callApi<T>(path: string, options: CallOptions = {}): Promise<T> {
  const token = storedToken();
  const subject = options.subject ?? 'that record';
  if (!token) throw new ApiError(401, 'Sign in to see this.');

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== '') search.set(key, String(value));
  }
  const suffix = search.toString() ? `?${search}` : '';

  const address = options.topLevel
    ? path
    : `/realms/${encodeURIComponent(options.realm ?? storedRealm())}${path}`;

  let response: Response;
  try {
    response = await fetch(apiUrl(`${address}${suffix}`), {
      method: options.method ?? 'GET',
      headers: {
        authorization: `Bearer ${token}`,
        ...(options.body ? { 'content-type': 'application/json' } : {}),
      },
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'The identity service could not be reached.');
  }

  if (!response.ok) {
    const problem = await response.json().catch(() => null) as { detail?: string; title?: string } | null;
    throw new ApiError(response.status, messageFor(response.status, problem?.detail ?? problem?.title ?? '', subject));
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

/** Formats a timestamp for reading, and says so plainly when there is not one. */
export function when(value?: string | null): string {
  if (!value) return 'never';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toLocaleString();
}

export function startOfToday(): string {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
}
