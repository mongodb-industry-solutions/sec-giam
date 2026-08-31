import { FastifyInstance } from 'fastify';

// Signing key custody, rotation and publication. Private material never lands unwrapped in the
// database; what the database holds is the published key set every verifier resolves against.
export async function keysModule(_fastify: FastifyInstance) {
  // Routes arrive with the module's own phase.
}
