import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { registrationController } from './controllers/registration.controller';
import { scimController } from './controllers/scim.controller';
import { credentialAdminController } from './controllers/credentialAdmin.controller';

// The principal store: identities of every kind, their credentials, and the agent, tool, MCP server
// and tenant registries. A human and a workload are the same kind of record here on purpose.
export async function directoryModule(fastify: FastifyInstance) {
  await fastify.register(registrationController, { prefix: API_PREFIX });
  await fastify.register(scimController, { prefix: API_PREFIX });
  await fastify.register(credentialAdminController, { prefix: API_PREFIX });
}
