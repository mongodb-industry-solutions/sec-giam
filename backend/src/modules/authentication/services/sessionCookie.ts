import { FastifyReply, FastifyRequest } from 'fastify';

/**
 * The browser's session, as a cookie.
 *
 * The authorization endpoint used to take `session_id` in a JSON body, on a route declared with no
 * security at all. Anyone holding a session id could mint authorization codes for any client, which
 * is a session identifier used as a bearer credential by whoever happens to have it.
 *
 * A cookie fixes the part that matters: the browser sends it, the browser cannot be persuaded to
 * hand it to a script, and it travels only to this origin. What it does NOT do is authenticate the
 * user agent, and that limit is stated rather than glossed. The mitigation for a stolen cookie is
 * the same as for a stolen session: revoke the session, which is a delete.
 *
 * No signing, and that is deliberate rather than an omission. A signed cookie protects a value the
 * server would otherwise have to trust; this value is a random UUID that is looked up in the session
 * collection, so a forged one resolves to nothing. Signing would add a key to manage and change no
 * outcome.
 */

export const SESSION_COOKIE = 'giam_session';

/**
 * `Lax` and not `Strict`.
 *
 * The flow this exists for is a TOP-LEVEL redirect from a relying party's origin to this one, which
 * `Strict` would refuse: the cookie would be withheld on exactly the navigation the authorization
 * endpoint is reached by, and every sign-in would appear to have expired. `Lax` sends it on a
 * top-level GET and withholds it on a cross-site POST, which is the distinction that matters here.
 *
 * `Secure` follows the request, so a local HTTP deployment still works while a deployment behind TLS
 * gets the attribute. Keyed off the protocol rather than off an environment name, because nothing
 * here asks which environment it is running in.
 */
function attributes(request: FastifyRequest, maxAgeSeconds?: number): string {
  const secure = request.protocol === 'https';
  return [
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    ...(secure ? ['Secure'] : []),
    ...(maxAgeSeconds !== undefined ? [`Max-Age=${maxAgeSeconds}`] : []),
  ].join('; ');
}

/** The session id the browser is carrying, or undefined. */
export function readSessionCookie(request: FastifyRequest): string | undefined {
  const header = request.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === SESSION_COOKIE) return decodeURIComponent(rest.join('=')) || undefined;
  }
  return undefined;
}

/**
 * Sets it, bounded by the session's own lifetime.
 *
 * Appended rather than assigned, so setting this never discards another `Set-Cookie` a handler has
 * already written.
 */
export function setSessionCookie(
  request: FastifyRequest,
  reply: FastifyReply,
  sessionId: string,
  maxAgeSeconds: number,
): void {
  const cookie = `${SESSION_COOKIE}=${encodeURIComponent(sessionId)}; ${attributes(request, maxAgeSeconds)}`;
  const existing = reply.getHeader('set-cookie');
  reply.header('set-cookie', existing
    ? [...(Array.isArray(existing) ? existing : [String(existing)]), cookie]
    : cookie);
}

/** Clears it on sign-out. `Max-Age=0` rather than a past date, which some agents disagree about. */
export function clearSessionCookie(request: FastifyRequest, reply: FastifyReply): void {
  reply.header('set-cookie', `${SESSION_COOKIE}=; ${attributes(request, 0)}`);
}
