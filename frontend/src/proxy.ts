import { NextRequest, NextResponse } from 'next/server';

/**
 * The same-origin proxy, moved out of `next.config.js`.
 *
 * `rewrites()` in `next.config.js` reads `process.env` once, at `next build`, and freezes the
 * result into `.next/routes-manifest.json`; `next start` serves that manifest and never calls the
 * function again. `GIAM_API_PRIVATE_URL` is deliberately not available at build time (the whole
 * point is one image working in every environment), so the Docker build always froze the fallback,
 * `http://localhost:8085`, no matter what the container's own environment said at runtime.
 *
 * Middleware has no such freeze: it runs on every request, in the running server process, reading
 * `process.env` fresh each time. This is what "resolved at runtime" actually requires in Next.js.
 */
export function proxy(request: NextRequest): NextResponse {
  const apiUrl = (
    process.env.GIAM_API_PRIVATE_URL
    || process.env.NEXT_PUBLIC_GIAM_API_URL
    || 'http://localhost:8085'
  ).replace(/\/+$/, '');

  const target = new URL(`${request.nextUrl.pathname}${request.nextUrl.search}`, apiUrl);
  return NextResponse.rewrite(target);
}

/**
 * Everything the browser asks for that belongs to the API rather than to the console.
 *
 * `/admin/resource-servers` is listed one path at a time on purpose. The catalog write is documented
 * at that bare address (docs/issuer-contract.md), outside `/api/v1`, while `/admin` itself is where
 * the console's own pages live, so a blanket `/admin/:path*` would forward the panel to the API and
 * leave the operator with a 404 instead of a screen. Without these two entries the request stayed in
 * Next, which answered its own 404 page, and the panel showed that HTML as its error.
 */
export const config = {
  matcher: [
    '/api/:path*',
    '/.well-known/:path*',
    '/realms/:path*',
    '/health',
    '/doc',
    '/doc/:path*',
    '/admin/resource-servers',
    '/admin/resource-servers/:path*',
  ],
};
