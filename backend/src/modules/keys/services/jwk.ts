import { createHash } from 'crypto';
import type { KeyObject } from 'crypto';
import { createPublicKey } from 'crypto';
import type { Jwk } from '../models/signingKey.model';

/**
 * RFC 7638 JWK thumbprint, used as the key id.
 *
 * Derived from the key rather than assigned, so a replica that restarts and reloads the same private
 * key republishes the same kid instead of churning the key set. It also makes a kid collision between
 * two different keys impossible, which matters when the published set is the union of every replica's.
 */
export function thumbprintKid(publicKey: KeyObject): string {
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  // The canonical form: required members only, lexicographic order, no whitespace.
  const canonical = jwk.kty === 'RSA'
    ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
    : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');
}

/** Turns a public PEM into a publishable JWK. Public parameters only, by construction. */
export function pemToJwk(publicKeyPem: string, kid: string, alg: 'RS256' | 'ES256'): Jwk {
  const key = createPublicKey(publicKeyPem);
  const jwk = key.export({ format: 'jwk' }) as Record<string, unknown>;
  // export({format:'jwk'}) on a public key emits no private parameter; asserted rather than assumed,
  // because publishing one would hand out the signer.
  for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
    if (jwk[priv] !== undefined) throw new Error('Refusing to publish a JWK carrying private parameters');
  }
  return { ...jwk, kid, use: 'sig', alg } as Jwk;
}
