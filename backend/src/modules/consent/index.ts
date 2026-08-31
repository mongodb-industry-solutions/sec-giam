import { FastifyInstance } from 'fastify';
import { grantController } from './controllers/grant.controller';

// Two different things, kept apart: a grant is a principal consenting to a client's scopes, a
// delegation is a principal authorising an agent to act on their behalf, purpose bound and revocable.
export async function consentModule(fastify: FastifyInstance) {
  await fastify.register(grantController);
}
