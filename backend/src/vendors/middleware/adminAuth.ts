import { FastifyRequest, FastifyReply } from 'fastify';
import { timingSafeEqual } from 'crypto';
import { config } from '../../config';

/**
 * The operational surface guard, until GIAM issues its own administrative tokens.
 *
 * When no token is configured the surface is CLOSED, not open: a capability that is not configured is
 * absent rather than faked, and an identity service that publishes its diagnostics to anyone who asks
 * because nobody set a variable is the failure this rule exists to prevent. It refuses the same way in
 * every deployment, because no behaviour here depends on which environment this is.
 */
export async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const expected = config.app.adminToken;
  if (!expected) {
    return reply.status(503).send({
      type: 'about:blank',
      title: 'Administrative surface not configured',
      status: 503,
      detail: 'GIAM_ADMIN_TOKEN is not set, so this surface has no credential to check against.',
    });
  }

  const header = request.headers.authorization ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return reply.status(401).send({
      type: 'about:blank',
      title: 'Unauthorized',
      status: 401,
      detail: 'A valid administrative bearer token is required.',
    });
  }
}
