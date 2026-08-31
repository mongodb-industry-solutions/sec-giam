import { FastifyInstance } from 'fastify';
import { registrationController } from './controllers/registration.controller';
import { scimController } from './controllers/scim.controller';

// The principal store: identities of every kind, their credentials, and the agent, tool, MCP server
// and tenant registries. A human and a workload are the same kind of record here on purpose.
export async function directoryModule(fastify: FastifyInstance) {
  await fastify.register(registrationController);
  await fastify.register(scimController);
}
