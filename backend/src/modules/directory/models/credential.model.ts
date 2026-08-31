import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * One collection for every authentication factor, discriminated by type.
 *
 * Separating credentials from the principal is what lets a subject hold several factors, lets one be
 * revoked without touching the others, and lets a new factor type arrive without altering the
 * identity record. It is also what stops a directory read from carrying credential material by
 * accident: the two are simply not in the same document.
 */

export type CredentialType = 'password' | 'public_key' | 'client_secret' | 'totp' | 'recovery_code';

/** NIST SP 800-63 authenticator assurance. Recorded per credential, since it is a property of one. */
export interface Assurance {
  level: 'aal1' | 'aal2' | 'aal3';
  method: string;
  verifiedAt?: string;
}

export interface CredentialRecord extends Scoped {
  credentialId: string;
  subjectId: string;
  type: CredentialType;

  /** bcrypt, for `password` and `client_secret`. Salted, so it is verified rather than looked up. */
  secretHash?: string;

  /** For `public_key`: what the authenticator registered. Public material only, by definition. */
  publicKeyPem?: string;
  algorithm?: 'ES256' | 'RS256';
  /**
   * The authenticator's own counter.
   *
   * A signature arriving with a counter at or below the stored one means the same authenticator
   * appears to exist twice, which is the definition of a cloned device.
   */
  signCount?: number;

  label?: string;
  status: 'active' | 'revoked';
  assurance: Assurance;

  createdAt: string;
  lastUsedAt?: string;
  expiresAt?: string;
  meta: Meta;
}

export function isUsable(credential: Pick<CredentialRecord, 'status' | 'expiresAt'>, now = new Date()): boolean {
  if (credential.status !== 'active') return false;
  // An expiry that has passed is a refusal, not a warning: a credential is either current or it is not.
  return !credential.expiresAt || Date.parse(credential.expiresAt) > now.getTime();
}
