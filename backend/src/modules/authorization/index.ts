import { FastifyInstance } from 'fastify';
import { resourceServerController } from './controllers/resourceServer.controller';

// The decision point: resource servers declare their enforcement points, the authority grants them
// through roles, policies and relationships. The application never stores an assignment.
export async function authorizationModule(fastify: FastifyInstance) {
  await fastify.register(resourceServerController);
}
