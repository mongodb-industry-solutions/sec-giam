import { FastifyInstance } from 'fastify';
import { reconcileController } from './controllers/reconcile.controller';
import { bindProvisioningTargets } from './services/webhookTarget';

// Outbound identity lifecycle. A change here reaches a consumer by push, and reconciliation covers
// the case where the push did not arrive: neither half is sufficient on its own.
export async function provisioningModule(fastify: FastifyInstance) {
  bindProvisioningTargets(fastify.db);
  await fastify.register(reconcileController);
}
