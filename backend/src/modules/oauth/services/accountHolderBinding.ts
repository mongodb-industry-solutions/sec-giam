/**
 * Which account holder a token should name, for the audience it is addressed to.
 *
 * A person holds records at more than one institution and each names them with its OWN reference:
 * the payment provider's party id is not the bank's account holder id. One reference on the
 * principal could only ever carry one of them, so a token addressed to the bank carried the
 * provider's and the bank filtered its records by something that names nothing there.
 *
 * Kept out of the issuer as a pure function because it is a decision, not a step: it is worth
 * stating on its own terms and worth testing without minting a token.
 */

/**
 * @param perAudience The principal's references, keyed by resource server audience.
 * @param fallback The single reference, used for an audience `perAudience` does not name. That is
 *   every principal bound to one application, which needs nothing new to keep working.
 * @param audience The audiences this token is addressed to.
 *
 * Fails CLOSED on ambiguity: a token addressed to two servers that bind this subject to different
 * records cannot say which the claim means, and a self-scoped resource server refuses a caller with
 * no binding rather than serving it somebody else's records. Narrowing the audience (RFC 8707)
 * brings the claim back.
 */
export function accountHolderForAudience(
  perAudience: Record<string, string> | undefined,
  fallback: string | undefined,
  audience: string[],
): string | undefined {
  if (!perAudience) return fallback;

  const matched = [...new Set(audience.map((name) => perAudience[name]).filter(Boolean))];
  if (matched.length === 1) return matched[0];
  if (matched.length > 1) {
    console.warn(
      `[oauth] the subject is bound to ${matched.length} different account holders across this `
      + `token's audience (${audience.join(', ')}), so no account_holder claim is issued. Ask for a `
      + 'single resource to obtain one.',
    );
    return undefined;
  }
  return fallback;
}
