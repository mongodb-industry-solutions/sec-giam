/**
 * What a token carries, after a client's request has been narrowed to what the subject holds.
 *
 * ADR section 8. A token carries `roles[]`, `permissions[]`, or both, and at least one.
 *
 * ROLES ARE THE DEFAULT, and the reason is a size limit rather than a preference. A JWT travels in
 * an HTTP header and proxies commonly cut around 8 KB. A token carrying three hundred expanded
 * permissions is a token that fails intermittently in production, on whichever proxy the request
 * happens to cross, and is very hard to diagnose from either end. Three roles expanded at the
 * decision point is the only form that scales.
 *
 * A client may ask for specific permissions instead, when it wants a narrower token than its roles
 * would give it, and that is worth supporting because it shrinks blast radius.
 */

export interface Attenuated {
  /** The permission strings the token will carry. Empty when the request was roles only. */
  permissions: string[];
  /** The roles the token will carry. */
  roles: string[];
  /**
   * What was asked for and refused.
   *
   * Returned rather than logged here, so the caller records it against the realm and the subject it
   * concerns. A drop nobody can see is a client quietly operating on a wrong idea of its authority.
   */
  dropped: string[];
}

/**
 * Intersects a request with what the roles actually grant.
 *
 * THE INVARIANT: a token may only narrow, never widen. A requested permission not covered by the
 * subject's roles is dropped, which is what makes it safe for a client to ask at all.
 *
 * Dropping rather than refusing is deliberate. Refusing the whole request would make a client that
 * asks for one permission too many fail entirely, and the rational response to that is to stop
 * asking and take the widest token on offer. Dropping keeps the narrow request worth making.
 */
export function attenuate(input: {
  /** Everything the subject's roles grant, resolved by the decision point. */
  held: string[];
  /** What the client asked for, if it asked. */
  requested?: string[];
  roles: string[];
}): Attenuated {
  // No request: roles only, which is the default and the form that scales.
  if (!input.requested?.length) {
    return { permissions: [], roles: input.roles, dropped: [] };
  }

  const held = new Set(input.held);
  const granted: string[] = [];
  const dropped: string[] = [];

  for (const permission of input.requested) {
    // `*` is not a way to ask for everything. A wildcard request would be a widening dressed as a
    // narrowing, which is the one thing this function exists to prevent.
    if (permission !== '*' && held.has(permission)) granted.push(permission);
    else dropped.push(permission);
  }

  /**
   * The roles travel with the narrowed permissions rather than instead of them.
   *
   * A resource server that checks roles keeps working when a client narrows, and one that checks
   * permissions gets exactly the narrowed set. Dropping the roles here would silently break the
   * first kind the moment any client started asking.
   */
  return {
    permissions: [...new Set(granted)].sort(),
    roles: input.roles,
    dropped: [...new Set(dropped)].sort(),
  };
}

/**
 * A rough size for the claims a token will carry, in bytes.
 *
 * Measured rather than assumed, because the 8 KB header limit is the thing that actually bites and
 * "it should be small enough" is how a token ends up too big on one proxy and fine on every other.
 */
export function claimsSize(claims: Record<string, unknown>): number {
  return Buffer.byteLength(JSON.stringify(claims), 'utf8');
}
