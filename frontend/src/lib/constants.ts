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
