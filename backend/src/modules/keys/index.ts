import { FastifyInstance } from 'fastify';
import { signingKeyController } from './controllers/signingKey.controller';

// Signing key custody, rotation and publication. Private material never lands unwrapped in the
// database; what the database holds is the published key set every verifier resolves against.
export async function keysModule(fastify: FastifyInstance) {
  await fastify.register(signingKeyController);
}
