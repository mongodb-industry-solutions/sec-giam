import { createPublicKey, verify as cryptoVerify } from 'crypto';
import type { TokenFormat } from '../../../shared/ports';
import { KeyRing } from '../../keys/services/keyRing.service';

/**
 * The JWT access-token profile, RFC 9068.
 *
 * Signing goes through the key ring rather than a key, so this format has no idea which custody mode
 * is in force and works unchanged whether the private half is on this node, behind a wrapping key or
 * inside a KMS.
 *
 * `typ: at+jwt` is the RFC 9068 header and it is not decoration: it stops an ID token or any other
 * JWT the authority signs from being presented as an access token, which is a real confusion attack
 * and not a theoretical one.
 */

function base64url(value: Buffer | string): string {
  return Buffer.from(value).toString('base64url');
}

export class JwtTokenFormat implements TokenFormat {
  readonly name = 'jwt';

  readonly locallyVerifiable = true;

  constructor(private readonly ring: KeyRing, private readonly realmId: string, private readonly typ = 'at+jwt') {}

  async issue(claims: Record<string, unknown>, kid: string): Promise<string> {
    const header = base64url(JSON.stringify({ alg: 'RS256', typ: this.typ, kid }));
    const payload = base64url(JSON.stringify(claims));
    const signingInput = `${header}.${payload}`;
    const { signature } = await this.ring.sign(this.realmId, Buffer.from(signingInput));
    return `${signingInput}.${signature.toString('base64url')}`;
  }

  /**
   * Reads the claims WITHOUT verifying.
   *
   * Named `inspect` for that reason: it is what a caller uses to find out which key to check against,
   * and a caller that stops here has verified nothing. Verification is `verify` below, and keeping
   * them apart is what stops the two being confused at a call site.
   */
  async inspect(token: string): Promise<Record<string, unknown> | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  /** The header, so a verifier can resolve the key id before trusting anything else. */
  async header(token: string): Promise<Record<string, unknown> | null> {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      return JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }

  /**
   * Verifies a token against the realm's PUBLISHED key set.
   *
   * Every classic JWT verification defect is refused explicitly rather than by omission, because each
   * one is an accepted forgery rather than a failed parse:
   *
   * - `alg: none` would make an unsigned token valid.
   * - A symmetric algorithm would let a holder of the PUBLIC key sign tokens, since a public key is
   *   published to everyone by design.
   * - `jku`, `jwk`, `x5u` and `x5c` let a token nominate the key that validates it, which is the
   *   token asserting its own authenticity.
   * - An unknown `kid` must be refused rather than resolved to whatever key happens to be at hand.
   */
  async verify(token: string, expected: { issuer: string; audience: string }): Promise<Record<string, unknown> | null> {
    const header = await this.header(token);
    if (!header) return null;

    if (header.alg !== 'RS256') return null;
    if (header.jku || header.jwk || header.x5u || header.x5c) return null;
    if (typeof header.kid !== 'string') return null;
    if (header.typ && header.typ !== this.typ) return null;

    const keySet = await this.ring.publishedKeySet(this.realmId);
    const jwk = keySet.keys.find((key) => key.kid === header.kid);
    if (!jwk) return null;
    if (jwk.alg !== 'RS256') return null;

    const [rawHeader, rawPayload, rawSignature] = token.split('.');
    const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
    const ok = cryptoVerify(
      'sha256',
      Buffer.from(`${rawHeader}.${rawPayload}`),
      publicKey,
      Buffer.from(rawSignature, 'base64url'),
    );
    if (!ok) return null;

    const claims = await this.inspect(token);
    if (!claims) return null;

    if (claims.iss !== expected.issuer) return null;
    const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audience.includes(expected.audience)) return null;

    // A small skew allowance, because clocks differ and a token minted one second in the caller's
    // future is a clock problem rather than a forgery.
    const now = Math.floor(Date.now() / 1000);
    const skew = 60;
    if (typeof claims.exp === 'number' && claims.exp + skew < now) return null;
    if (typeof claims.nbf === 'number' && claims.nbf - skew > now) return null;

    return claims;
  }
}
