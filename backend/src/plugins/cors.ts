import fp from 'fastify-plugin';
import cors from '@fastify/cors';
import { FastifyInstance } from 'fastify';
import { config } from '../config';

// GIAM is browser reachable, unlike the bank: the login, consent and administration screens are a
// separate origin, and the discovery and JWKS documents are public by specification.
function buildOrigin(): string | string[] | boolean {
  const configured = config.server.corsOrigin;
  if (!configured || configured === '*') return true;

  const origins = configured.split(',').map((o) => o.trim()).filter(Boolean);

  // The API's own origin, since Swagger UI is co-hosted.
  const port = String(config.server.port);
  for (const self of [`http://localhost:${port}`, `http://127.0.0.1:${port}`]) {
    if (!origins.includes(self)) origins.push(self);
  }

  return origins.length === 1 ? origins[0] : origins;
}

async function corsPlugin(fastify: FastifyInstance) {
  await fastify.register(cors, {
    origin: buildOrigin(),
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'If-Match', 'Idempotency-Key', 'X-Request-ID', 'DPoP'],
    exposedHeaders: ['ETag', 'X-Request-ID'],
    credentials: true,
  });
}

export default fp(corsPlugin, { name: 'cors' });
