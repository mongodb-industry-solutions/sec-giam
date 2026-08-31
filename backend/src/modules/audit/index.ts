import { FastifyInstance } from 'fastify';
import { securityEventController } from './controllers/securityEvent.controller';

// Security events and the streams that deliver them. Identity evidence only: a consumer's business
// action outcome belongs to the consumer, and recording it here would duplicate two sources of truth.
export async function auditModule(fastify: FastifyInstance) {
  await fastify.register(securityEventController);
}
