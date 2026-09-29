import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { signingKeyController } from './controllers/signingKey.controller';

// Signing key custody, rotation and publication. Private material never lands unwrapped in the
// database; what the database holds is the published key set every verifier resolves against.
export async function keysModule(fastify: FastifyInstance) {
  await fastify.register(signingKeyController, { prefix: API_PREFIX });
}
