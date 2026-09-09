/** @type {import('next').NextConfig} */
// The repo-root .env configures every app in local dev. Guarded, because in a Docker build the
// context is this directory alone and the values come from the container environment instead.
try { require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') }); } catch { /* no root .env in this context */ }

const { version: FRONTEND_VERSION } = require('./package.json');

const nextConfig = {
  env: {
    NEXT_PUBLIC_GIAM_FRONTEND_VERSION: FRONTEND_VERSION,
    // The issuer base the console talks to. Public, because the browser resolves it directly.
    NEXT_PUBLIC_GIAM_API_URL: process.env.NEXT_PUBLIC_GIAM_API_URL || '',
  },
  allowedDevOrigins: ['127.0.0.1', 'localhost'],
  // The same-origin proxy (API, well-known, realms, health, doc) lives in `src/middleware.ts`, not
  // here: `rewrites()` is evaluated once at `next build` and frozen into `routes-manifest.json`,
  // which is exactly wrong for a value (`GIAM_API_PRIVATE_URL`) that is only ever set at container
  // runtime. Middleware re-reads the environment on every request instead.
};

module.exports = nextConfig;
