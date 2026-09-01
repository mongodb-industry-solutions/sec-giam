import { FastifyInstance } from 'fastify';
import { resourceServerController } from './controllers/resourceServer.controller';
import { roleController } from './controllers/role.controller';
import { crossRealmController } from './controllers/crossRealm.controller';
import { policyController } from './controllers/policy.controller';

// The decision point: resource servers declare their enforcement points, the authority grants them
// through roles, policies and relationships. The application never stores an assignment.
export async function authorizationModule(fastify: FastifyInstance) {
  await fastify.register(resourceServerController);
  await fastify.register(crossRealmController);
  await fastify.register(roleController);
  await fastify.register(policyController);
}
