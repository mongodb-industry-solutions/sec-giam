import fp from 'fastify-plugin';
import { FastifyInstance, FastifyRequest } from 'fastify';
import { v4 as uuidv4 } from 'uuid';

// One identifier per call, echoed back, stamped on every security event the call produces. It is what
// lets an identity trail and a consumer's action trail be read as one story without either service
// knowing the other's schema.
declare module 'fastify' {
  interface FastifyRequest {
    correlationId: string;
  }
}

export const REQUEST_ID_HEADER = 'x-request-id';

// A caller that sends no id is still traceable: one is generated rather than left empty.
function resolveCorrelationId(request: FastifyRequest): string {
  const header = request.headers[REQUEST_ID_HEADER];
  const value = Array.isArray(header) ? header[0] : header;
  return value?.trim() || uuidv4();
}

async function correlationPlugin(fastify: FastifyInstance) {
  fastify.decorateRequest('correlationId', '');

  fastify.addHook('onRequest', async (request, reply) => {
    request.correlationId = resolveCorrelationId(request);
    reply.header(REQUEST_ID_HEADER, request.correlationId);
  });
}

export default fp(correlationPlugin, { name: 'correlation' });
