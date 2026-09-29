// Everything the console needs to reach the identity API, resolved in one place.
//
// An empty base means "same origin": the Next.js rewrites forward to the API server side, so the
// browser never makes a cross-origin call and no deployment needs a CORS entry to work.
export const env = {
  apiBaseUrl: (process.env.NEXT_PUBLIC_GIAM_API_URL || '').replace(/\/+$/, ''),
} as const;

/** This service's versioned API; a realm's issuer and protocol routes live under it too. */
export const API_PREFIX = '/api/v1';

export function apiUrl(path: string): string {
  return `${env.apiBaseUrl}${path.startsWith('/') ? path : `/${path}`}`;
}

/**
 * The same path as a URL object, for the callers that add query parameters or navigate to it.
 *
 * The base matters: with `apiBaseUrl` empty, `apiUrl` returns a ROOT-RELATIVE path, and `new URL`
 * rejects a relative string given no base. Building one without this is how signing in ended on
 * "Returning you to the application" and stayed there, the throw swallowed by the caller's catch.
 * Browser only, which every caller is.
 */
export function apiUrlObject(path: string): URL {
  return new URL(apiUrl(path), window.location.origin);
}

// The BROWSER-reachable API host, for links a person clicks rather than calls the console makes. An
// empty apiBaseUrl means same origin, which a rewrite serves but a new tab cannot open.
export const API_PUBLIC_URL =
  process.env.NEXT_PUBLIC_GIAM_API_PUBLIC_URL
  || process.env.NEXT_PUBLIC_GIAM_API_URL
  || 'http://localhost:8085';
