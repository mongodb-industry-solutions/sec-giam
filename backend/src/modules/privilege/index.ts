import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { elevationController } from './controllers/elevation.controller';

// Privileged access: authority granted for a stated reason, bound to one thing, and taken back
// automatically. A record rather than only a signed token, so it can be listed and revoked.
export async function privilegeModule(fastify: FastifyInstance) {
  await fastify.register(elevationController, { prefix: API_PREFIX });
}
