import { FastifyRequest, FastifyReply } from 'fastify';
import { timingSafeEqual, createHash } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { config } from '../../config';
import { derivedSecret } from '../../shared/services/secrets';
import { problem } from '../../shared/models/problem';

/**
 * The operational surface guard.
 *
 * Two credentials are accepted and they are not equivalent. The configured token is the break-glass
 * one, held by whoever deploys the service; the session token is what the console mints when an
 * operator signs in, and it expires on its own. Both are checked here so no route has to decide.
 *
 * When neither a token nor a sign-in credential is configured the surface is CLOSED, not open: a
 * capability that is not configured is absent rather than faked, and an identity service that
 * publishes its diagnostics to anyone who asks because nobody set a variable is the failure this rule
 * exists to prevent. It refuses the same way in every deployment, because no behaviour here depends on
 * which environment this is.
 */

const ADMIN_SESSION_PURPOSE = 'giam:admin-session';
const ADMIN_SESSION_TTL = '4h';

interface AdminClaims extends jwt.JwtPayload {
  role?: string;
}

/** The key the console's operator session is signed with. Never the configured token itself. */
function sessionKey(): string {
  return derivedSecret(ADMIN_SESSION_PURPOSE);
}

export function issueAdminToken(operator: string): string {
  return jwt.sign({ sub: operator, role: 'admin' }, sessionKey(), { expiresIn: ADMIN_SESSION_TTL });
}

/** The operator name the console signs in as, and the digest of the password it must present. */
export function adminCredential(): { user: string; passwordDigest: string } | null {
  const user = config.app.adminUser;
  const digest = config.app.adminPasswordSha256;
  if (!user || !digest) return null;
  return { user, passwordDigest: digest };
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function constantTimeEquals(presented: string, expected: string): boolean {
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** True when the header carries either accepted credential. Used by hijacked streams too. */
export function isAdminAuthorized(authorization: string | undefined): boolean {
  const presented = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!presented) return false;

  const configured = config.app.adminToken;
  if (configured && constantTimeEquals(presented, configured)) return true;

  try {
    const claims = jwt.verify(presented, sessionKey()) as AdminClaims;
    return claims.role === 'admin';
  } catch {
    return false;
  }
}

/** True when at least one way of proving operator identity is configured. */
export function adminSurfaceConfigured(): boolean {
  return Boolean(config.app.adminToken) || adminCredential() !== null;
}

export async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!adminSurfaceConfigured()) {
    return reply.status(503).send(problem(
      503,
      'Administrative surface not configured',
      'Neither GIAM_ADMIN_TOKEN nor GIAM_ADMIN_USER and GIAM_ADMIN_PASSWORD_SHA256 are set, so this '
      + 'surface has no credential to check against.',
    ));
  }

  if (!isAdminAuthorized(request.headers.authorization)) {
    return reply.status(401).send(problem(
      401,
      'Unauthorized',
      'A valid administrative bearer token is required.',
    ));
  }
}
