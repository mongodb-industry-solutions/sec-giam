import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { discoveryController } from './controllers/discovery.controller';
import { tokenController } from './controllers/token.controller';
import { authorizeController } from './controllers/authorize.controller';
import { introspectController } from './controllers/introspect.controller';
import { clientRegistrationController } from './controllers/registration.controller';
import { userinfoController } from './controllers/userinfo.controller';

// The authorization server: discovery, the published key set, and the token endpoint. Every route
// here implements a specification verbatim, so the paths carry the standard's own shape rather than
// this project's.
export async function oauthModule(fastify: FastifyInstance) {
  await fastify.register(discoveryController);
  await fastify.register(userinfoController, { prefix: API_PREFIX });
  await fastify.register(authorizeController, { prefix: API_PREFIX });
  await fastify.register(tokenController, { prefix: API_PREFIX });
  await fastify.register(introspectController, { prefix: API_PREFIX });
  await fastify.register(clientRegistrationController, { prefix: API_PREFIX });
}
