import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { resourceController } from './controllers/resource.controller';
import { resourceCatalogController } from './controllers/resourceCatalog.controller';
import { signalsController } from './controllers/signals.controller';
import { roleController } from './controllers/role.controller';
import { crossRealmController } from './controllers/crossRealm.controller';
import { policyController } from './controllers/policy.controller';

// The decision point: resource servers declare their enforcement points, the authority grants them
// through roles, policies and relationships. The application never stores an assignment.
export async function authorizationModule(fastify: FastifyInstance) {
  await fastify.register(resourceController, { prefix: API_PREFIX });
  await fastify.register(resourceCatalogController, { prefix: API_PREFIX });
  await fastify.register(signalsController, { prefix: API_PREFIX });
  await fastify.register(crossRealmController, { prefix: API_PREFIX });
  await fastify.register(roleController, { prefix: API_PREFIX });
  await fastify.register(policyController, { prefix: API_PREFIX });
}
