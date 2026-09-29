import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { loginController } from './controllers/login.controller';
import { logoutController } from './controllers/logout.controller';
import { rosterController } from './controllers/roster.controller';
import { backchannelController } from './controllers/backchannel.controller';
import { enrollmentController } from './controllers/enrollment.controller';
import { sessionController } from './controllers/session.controller';

// How a principal proves who it is, and the session that results. One pipeline: an employee signing
// in and a microservice presenting a credential differ only in the authentication method they use.
export async function authenticationModule(fastify: FastifyInstance) {
  await fastify.register(loginController, { prefix: API_PREFIX });
  await fastify.register(rosterController, { prefix: API_PREFIX });
  await fastify.register(enrollmentController, { prefix: API_PREFIX });
  await fastify.register(backchannelController, { prefix: API_PREFIX });
  await fastify.register(logoutController, { prefix: API_PREFIX });
  await fastify.register(sessionController, { prefix: API_PREFIX });
}
