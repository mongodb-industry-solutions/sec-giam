import { Meta, Scoped } from '../../../shared/models/base.model';
import type { KeyProviderName } from '../../../config';

/**
 * A published signing key.
 *
 * What is stored is PUBLIC material and a reference to where the private half lives. An unwrapped
 * private PEM in this collection would be the compromise the whole custody design exists to prevent,
 * and validation refuses a document carrying one.
 *
 * The lease fields are what make more than one replica correct. Each replica holds its own private
 * key and publishes only its public half here, so the JWKS a realm serves is the UNION of every
 * active public key and every replica publishes an identical set. A token signed by one therefore
 * verifies at any other, and at every resource server, with no shared secret anywhere.
 */
export interface SigningKeyRecord extends Scoped {
  keyId: string;
  /** RFC 7638 thumbprint of the public JWK. Deterministic, so a restart republishes the same kid. */
  kid: string;
  alg: 'RS256' | 'ES256';
  use: 'sig';
  publicKeyPem: string;
  keySize?: number;
  status: 'active' | 'deprecated' | 'revoked';
  provider: KeyProviderName;
  /** Set only by the kms provider: where the private key actually lives. */
  kmsKeyArn?: string;
  /**
   * The private key, envelope-encrypted under a key held OUTSIDE the database. Set only by the
   * shared-store provider. A wrapped key in the database is useless to anyone who obtains only the
   * database; a plaintext PEM is a compromise. That distinction is the entire point of the field.
   */
  wrappedPrivateKey?: string;
  /** Which replica owns the private half. Absent when custody is external or shared. */
  instanceId?: string;
  /** Renewed on a heartbeat. Past it the key stops signing but stays published. */
  leaseExpiresAt?: string;
  /** False once the lease has lapsed: still trusted for verification, no longer offered for signing. */
  signingEligible: boolean;
  notBefore: string;
  /**
   * When the key stops being published.
   *
   * Set to the lease lapse plus a grace of at least the maximum token lifetime. Removing a key
   * earlier would invalidate live sessions on a scale-down, which is the failure this field exists
   * to prevent.
   */
  notAfter?: string;
  rotatedAt?: string;
  meta: Meta;
}

/** A public key in RFC 7517 form. Only public parameters ever appear here. */
export interface Jwk {
  kty: string;
  kid: string;
  use: 'sig';
  alg: string;
  [parameter: string]: unknown;
}

export interface JwkSet {
  keys: Jwk[];
}

/** Refuses a document that would put private material in the database in the clear. */
export function assertNoPlaintextPrivateKey(record: Pick<SigningKeyRecord, 'publicKeyPem' | 'wrappedPrivateKey'>): void {
  const suspect = `${record.publicKeyPem ?? ''}${record.wrappedPrivateKey ?? ''}`;
  if (/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(suspect)) {
    throw new Error('A signing key record must never carry an unwrapped private key');
  }
}
