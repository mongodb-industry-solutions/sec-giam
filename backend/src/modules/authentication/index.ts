import { FastifyInstance } from 'fastify';
import { loginController } from './controllers/login.controller';
import { logoutController } from './controllers/logout.controller';
import { rosterController } from './controllers/roster.controller';
import { backchannelController } from './controllers/backchannel.controller';
import { enrollmentController } from './controllers/enrollment.controller';

// How a principal proves who it is, and the session that results. One pipeline: an employee signing
// in and a microservice presenting a credential differ only in the authentication method they use.
export async function authenticationModule(fastify: FastifyInstance) {
  await fastify.register(loginController);
  await fastify.register(rosterController);
  await fastify.register(enrollmentController);
  await fastify.register(backchannelController);
  await fastify.register(logoutController);
}
