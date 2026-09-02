/**
 * The authority's own addresses, for the operations panel.
 *
 * Deliberately small. The provider's equivalent file carries its product's constants too, and copying
 * it wholesale is how an identity authority ends up with a merchant URL in it. Only what the panel
 * needs is here.
 */

// Browser-reachable API host, for links a person opens and for the docs.
export const BACKEND_PUBLIC_URL =
  process.env.NEXT_PUBLIC_GIAM_API_PUBLIC_URL
  || process.env.NEXT_PUBLIC_GIAM_API_URL
  || 'http://localhost:8085';

/**
 * Base for fetch and server-sent streams.
 *
 * Empty means same origin, which the Next rewrites forward server side, so no deployment needs a CORS
 * entry for the console. It is only non-empty when there is no private address to forward to.
 */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_GIAM_API_URL !== undefined && process.env.NEXT_PUBLIC_GIAM_API_URL !== ''
    ? ''
    : BACKEND_PUBLIC_URL;

/**
 * A registered relying party the simulator can send somebody to, so the authorization code flow is
 * shown from the side that consumes it rather than only from the side that issues it.
 *
 * It is an address, not a domain concept: what the application sells is none of this authority's
 * business, and the card only needs somewhere to point. Unset means the environment does not publish
 * one, and the card says so instead of offering a link that fails.
 */
export const RELYING_PARTY_PUBLIC_URL =
  process.env.NEXT_PUBLIC_GIAM_URL_RELYING_PARTY
  || (process.env.NODE_ENV === 'development' ? 'http://localhost:8082' : '');

// Shareable address of this demo: the live browser origin, which is correct in every environment,
// with an override for the case where the origin somebody reached is not the one to hand out.
export function demoPublicUrl(path = ''): string {
  const base = (
    process.env.NEXT_PUBLIC_GIAM_URL_FRONTEND
    || (typeof window !== 'undefined' ? window.location.origin : '')
  ).replace(/\/+$/, '');
  return `${base}${path}`;
}

// The realm the simulator walks. One name, so the discovery link and the sign-in card cannot drift.
export const SIMULATOR_REALM = process.env.NEXT_PUBLIC_GIAM_REALM || 'leafypay';

// Served by the API host, and the one document that proves the endpoints below it are real.
export const DISCOVERY_URL = `${BACKEND_PUBLIC_URL}/realms/${SIMULATOR_REALM}/.well-known/openid-configuration`;

// The API reference, on the same host as the API it documents.
export const API_DOC_URL = `${BACKEND_PUBLIC_URL}/doc`;
