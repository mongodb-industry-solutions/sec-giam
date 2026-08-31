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
  async rewrites() {
    // Same-origin proxy: the browser never makes a cross-origin call to the identity API, so there is
    // no CORS dependency and no need to publish the API separately from the console.
    const apiUrl = (
      process.env.GIAM_API_PRIVATE_URL
      || process.env.NEXT_PUBLIC_GIAM_API_URL
      || 'http://localhost:8085'
    ).replace(/\/+$/, '');
    return [
      { source: '/api/:path*', destination: `${apiUrl}/api/:path*` },
      // The protocol surfaces, reachable through the console origin so a relying party configured
      // against the console keeps working without a second published host.
      { source: '/.well-known/:path*', destination: `${apiUrl}/.well-known/:path*` },
      { source: '/realms/:path*', destination: `${apiUrl}/realms/:path*` },
      { source: '/health', destination: `${apiUrl}/health` },
      { source: '/doc', destination: `${apiUrl}/doc` },
      { source: '/doc/:path*', destination: `${apiUrl}/doc/:path*` },
    ];
  },
};

module.exports = nextConfig;
