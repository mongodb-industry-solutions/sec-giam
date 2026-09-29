import { FastifyInstance } from 'fastify';
import { API_PREFIX } from '../../shared/models/routes';
import { adminController } from './controllers/admin.controller';
import { consoleController } from './controllers/console.controller';
import { operationsController } from './controllers/operations.controller';
import { deliveryInspectorController, noteInspectorReady } from './controllers/deliveryInspector.controller';

/**
 * The operational surface: diagnostics, the log buffer, the security posture report, the maintenance
 * the console drives, and a receiver for inspecting what this service sends.
 *
 * It sits under the versioned API path rather than at the root because the console reaches it through
 * the same origin it is served from, where `/admin` already belongs to the console's own pages. A
 * surface only reachable when the API is published separately is a surface that works in development
 * and not in a deployment.
 */
export const ADMIN_PREFIX = `${API_PREFIX}/admin`;

export async function adminModule(fastify: FastifyInstance) {
  await fastify.register(adminController, { prefix: ADMIN_PREFIX });
  await fastify.register(operationsController, { prefix: ADMIN_PREFIX });
  await fastify.register(deliveryInspectorController, { prefix: `${ADMIN_PREFIX}/webhook` });
  await fastify.register(consoleController, { prefix: ADMIN_PREFIX });
  noteInspectorReady(`${ADMIN_PREFIX}/webhook`);
}
