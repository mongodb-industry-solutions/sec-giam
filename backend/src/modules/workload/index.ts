import { FastifyInstance } from 'fastify';

// Workload identity: trust domains, attestation state, and exchanging an attested credential for a
// short-lived token. GIAM federates workload attestation rather than reimplementing it.
export async function workloadModule(_fastify: FastifyInstance) {
  // Routes arrive with the module's own phase.
}
