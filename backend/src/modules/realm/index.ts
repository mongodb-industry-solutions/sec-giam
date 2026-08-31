import { FastifyInstance } from 'fastify';
import { federationController } from './controllers/federation.controller';

// Realms and the upstream providers federated inside them. A realm is a trust and key boundary; an
// identityProvider row is how a third-party IdP joins one without any application learning of it.
export async function realmModule(fastify: FastifyInstance) {
  await fastify.register(federationController);
}
