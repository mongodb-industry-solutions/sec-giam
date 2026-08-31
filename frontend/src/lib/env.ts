// Everything the console needs to reach the identity API, resolved in one place.
//
// An empty base means "same origin": the Next.js rewrites forward to the API server side, so the
// browser never makes a cross-origin call and no deployment needs a CORS entry to work.
export const env = {
  apiBaseUrl: (process.env.NEXT_PUBLIC_GIAM_API_URL || '').replace(/\/+$/, ''),
} as const;

export function apiUrl(path: string): string {
  return `${env.apiBaseUrl}${path.startsWith('/') ? path : `/${path}`}`;
}

// The BROWSER-reachable API host, for links a person clicks rather than calls the console makes. An
// empty apiBaseUrl means same origin, which a rewrite serves but a new tab cannot open.
export const API_PUBLIC_URL =
  process.env.NEXT_PUBLIC_GIAM_API_PUBLIC_URL
  || process.env.NEXT_PUBLIC_GIAM_API_URL
  || 'http://localhost:8085';
