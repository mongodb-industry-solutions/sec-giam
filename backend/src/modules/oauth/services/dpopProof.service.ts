import { createPublicKey, createVerify } from 'crypto';
import { thumbprintKid } from '../../keys/services/jwk';

/**
 * DPoP proof verification, RFC 9449.
 *
 * Unlike an access token (`JwtTokenFormat`), where an embedded `jwk` in the header is refused as a
 * key-injection forgery signal, a DPoP proof REQUIRES one: the whole mechanism is the holder proving
 * which key it has by signing with it and showing its public half inline, because there is no prior
 * key set to look the key up in. The two verifiers must not be confused or merged.
 *
 * What this does NOT do, by design, scoped to what Part A of
 * `.agents/specs/dev.v01.plan-fix-credential-id.md` needs: no persistent cross-instance `jti` replay
 * cache. Section B.0 of that plan records why: a naive cache collection would be the exact kind of
 * ephemeral security bookkeeping ADR-001's "thirteen collections... no revocation entries" principle
 * refuses, and the two established alternatives (extending `TicketRecord.flow`, or a generation
 * counter like `refreshGen`) are an open decision, not one this file makes unilaterally. The `iat`
 * window below is the partial mitigation RFC 9449 section 11.1 itself names as acceptable on its own:
 * a proof outside a short acceptance window is refused regardless of whether its `jti` was ever seen
 * before. A proof replayed within that window is NOT caught here — flagged, not hidden.
 */

const SUPPORTED_ALG = new Set(['RS256', 'ES256']);

export interface VerifiedDpopProof {
  /** RFC 9449 section 6: the base64url SHA-256 JWK thumbprint, bound into the issued token's `cnf.jkt`. */
  jkt: string;
  jti: string;
}

function base64urlDecode(segment: string): Record<string, unknown> | null {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Verifies one DPoP proof against the request it was presented with.
 *
 * `htu` is compared with query and fragment stripped, per RFC 9449 section 4.3's own definition of
 * the claim: it names the request URI without those parts, so a proof is not refused over a query
 * string the client could not have predicted matching byte for byte.
 */
export function verifyDpopProof(
  proof: string,
  expected: { htm: string; htu: string; maxAgeSeconds?: number },
): VerifiedDpopProof | null {
  const parts = proof.split('.');
  if (parts.length !== 3) return null;

  const header = base64urlDecode(parts[0]);
  if (!header) return null;

  // `none` and a symmetric algorithm are both refused the same way RFC 9449 section 4.2 requires:
  // the proof is worthless if anyone, not only the holder, could have produced a valid signature.
  if (typeof header.alg !== 'string' || !SUPPORTED_ALG.has(header.alg)) return null;
  if (header.typ !== 'dpop+jwt') return null;
  if (!header.jwk || typeof header.jwk !== 'object') return null;

  const jwk = header.jwk as Record<string, unknown>;
  // A public key carries no private parameter. Refusing one that does is the same reasoning
  // `pemToJwk` applies in the opposite direction: an unchecked private member here would mean this
  // verifier trusted the presenter's own claim about what is public, instead of checking it.
  for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
    if (jwk[priv] !== undefined) return null;
  }

  let publicKey;
  try {
    publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
  } catch {
    return null;
  }

  const signingInput = `${parts[0]}.${parts[1]}`;
  let verified = false;
  try {
    verified = createVerify('sha256')
      .update(signingInput)
      .end()
      .verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url'));
  } catch {
    return null;
  }
  if (!verified) return null;

  const payload = base64urlDecode(parts[1]);
  if (!payload) return null;
  if (typeof payload.jti !== 'string' || !payload.jti) return null;
  if (typeof payload.htm !== 'string' || payload.htm.toUpperCase() !== expected.htm.toUpperCase()) return null;
  if (typeof payload.iat !== 'number') return null;

  if (typeof payload.htu !== 'string') return null;
  const stripQueryAndFragment = (uri: string) => uri.split(/[?#]/)[0];
  if (stripQueryAndFragment(payload.htu) !== stripQueryAndFragment(expected.htu)) return null;

  // Seconds to minutes per RFC 9449 section 11.1's own guidance, not left open-ended: a proof is a
  // claim about THIS instant, and accepting an old one defeats the freshness the mechanism exists for.
  const maxAge = expected.maxAgeSeconds ?? 60;
  const now = Math.floor(Date.now() / 1000);
  if (payload.iat > now + 5 || payload.iat < now - maxAge) return null;

  return { jkt: thumbprintKid(publicKey), jti: payload.jti };
}
