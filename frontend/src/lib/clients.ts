'use client';

/**
 * The application registry, as the console sees it.
 *
 * One place for the shape and for the redirect rules, so the list and the detail screen cannot drift
 * apart. Everything checked here is checked again by the authority: this exists to explain a refusal
 * before the round trip, never to be the thing that enforces it.
 */

/**
 * One owner of a registration.
 *
 * Ownership is a set and every owner holds the same authority: read, edit, rotate, withdraw. There is
 * no primary owner, so nothing here ranks them.
 */
export interface ClientOwner {
  kind: string;
  ref: string;
  display_name?: string;
  /** Whether this owner is the person reading the screen. Decided by the authority, not here. */
  is_caller?: boolean;
}

/**
 * The environments this platform is deployed to, in the order a screen should show them.
 *
 * The same three the authority resolves against. Named here rather than imported because the console
 * is a browser bundle and this is the only part of that vocabulary it needs.
 */
export const PLATFORM_ENVIRONMENTS = ['development', 'staging', 'production'] as const;
export type PlatformEnvironmentName = typeof PLATFORM_ENVIRONMENTS[number];

/**
 * Where an application answers, per environment.
 *
 * Declared on the registration so one registration serves a laptop, staging and production. A
 * relative `logo_uri` is resolved against the entry for whichever environment the authority is
 * running as, which is why the two fields belong together on the screen.
 */
export type ClientBaseUrls = Partial<Record<PlatformEnvironmentName, string>>;

export interface RegisteredClient {
  client_id: string;
  client_name: string;
  client_type?: 'confidential' | 'public';
  client_secret?: string;
  redirect_uris?: string[];
  post_logout_redirect_uris?: string[];
  grant_types?: string[];
  scope?: string;
  logo_uri?: string;
  base_url_by_environment?: ClientBaseUrls;
  application_type?: string;
  token_endpoint_auth_method?: string;
  require_pkce?: boolean;
  status?: string;
  owners?: ClientOwner[];
  owned_by_caller?: boolean;
  created_at?: string;
  last_modified_at?: string;
}

export interface ClientPage {
  clients: RegisteredClient[];
  total: number;
  limit: number;
  offset: number;
  /** What the listing covered: only the caller's own registrations, or the whole realm. */
  scope: 'self' | 'all';
}

/** The grants an ordinary owner may ask for. Anything wider is an administrator's decision. */
export const SELF_SERVICE_GRANTS = ['authorization_code', 'refresh_token'];

export const PRIVILEGED_GRANTS = [
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:token-exchange',
  'urn:openid:params:grant-type:ciba',
];

/** The sign-in scopes a self-registered application may request. */
export const SELF_SERVICE_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

/**
 * Checks one redirect URI the way the authority will.
 *
 * The authority compares a redirect EXACTLY and never by prefix, so every address an application can
 * return to has to be written out in full. A wildcard is refused rather than expanded, plain HTTP is
 * accepted only on a loopback address, and a fragment is refused because it is never sent to a
 * redirect endpoint in the first place.
 */
export function redirectUriProblem(uri: string): string | null {
  if (uri.includes('*')) return 'Wildcards are not allowed. Write every address in full.';
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return 'Not an absolute URI. Include the scheme, for example https://app.example/callback.';
  }
  if (parsed.hash) return 'A fragment is never sent to a redirect endpoint. Remove everything from the #.';
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback(parsed.hostname))) {
    return 'Must be HTTPS. Plain HTTP is accepted only on a loopback address.';
  }
  return null;
}

/**
 * Checks one application address the way the authority will use it.
 *
 * An ORIGIN, not an endpoint: it is the half a relative logo path is appended to, so a query or a
 * fragment on it would survive the join and produce a URL that asks for an icon with somebody's
 * search string still attached. Otherwise the same rules a redirect follows, through the same
 * function, so the two cannot disagree about what a usable address is.
 */
export function baseUrlProblem(url: string): string | null {
  const problem = redirectUriProblem(url);
  if (problem) return problem;
  const parsed = new URL(url);
  if (parsed.search) return 'A base address carries no query string. Remove everything from the ?.';
  return null;
}

/** The first problem in a set of per-environment addresses, named by its environment. */
export function firstBaseUrlProblem(urls: ClientBaseUrls): string | null {
  for (const environment of PLATFORM_ENVIRONMENTS) {
    const value = urls[environment]?.trim();
    if (!value) continue;
    const problem = baseUrlProblem(value);
    if (problem) return `${environment}: ${problem}`;
  }
  return null;
}

/** The addresses that were actually filled in, so an empty row is never stored as an empty string. */
export function filledBaseUrls(urls: ClientBaseUrls): ClientBaseUrls {
  const filled: ClientBaseUrls = {};
  for (const environment of PLATFORM_ENVIRONMENTS) {
    const value = urls[environment]?.trim();
    if (value) filled[environment] = value.replace(/\/$/, '');
  }
  return filled;
}

/** Whether two sets of addresses say the same thing, for a dirty check. */
export function sameBaseUrls(a: ClientBaseUrls, b: ClientBaseUrls): boolean {
  return PLATFORM_ENVIRONMENTS.every((name) => (a[name] ?? '') === (b[name] ?? ''));
}

/** How a set of owners reads in one line, with the reader named as themselves. */
export function ownersLabel(owners: ClientOwner[] | undefined): string {
  if (!owners || owners.length === 0) return 'nobody';
  return owners.map((owner) => (owner.is_caller ? 'you' : owner.display_name || owner.ref)).join(', ');
}

/** The first problem in a list of addresses, so a form can explain one thing at a time. */
export function firstRedirectProblem(uris: string[]): string | null {
  for (const uri of uris) {
    const problem = redirectUriProblem(uri);
    if (problem) return `${uri}: ${problem}`;
  }
  return null;
}
