import { FastifyInstance } from 'fastify';
import { adminController } from './controllers/admin.controller';
import { consoleController } from './controllers/console.controller';

// The operational surface: diagnostics, log buffer and the security posture report. Administrative
// routes live under /admin/ so a reader can tell them from a public protocol endpoint by the URL.
export async function adminModule(fastify: FastifyInstance) {
  await fastify.register(adminController, { prefix: '/admin' });
  // Declares its own full paths, so it is registered without the prefix.
  await fastify.register(consoleController);
}
