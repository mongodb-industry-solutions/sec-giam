import { FastifyInstance } from 'fastify';
import { systemController } from './controllers/system.controller';

// Infrastructure surface: health and readiness. Not part of the contract a consumer integrates
// against, which is why it is a module of its own rather than a route among the protocol endpoints.
export async function systemModule(fastify: FastifyInstance) {
  await fastify.register(systemController, { prefix: '/system' });
}
