import { createHmac, timingSafeEqual } from 'crypto';
import { config } from '../../config';

// Blind indexes: a keyed one-way digest of a value, stored in clear so it can carry a unique index
// that encrypted material cannot. It answers "is this value already registered" without answering
// "what is the value", which is the whole reason it exists next to the encrypted field.
//
// Keyed rather than a plain hash: an unkeyed digest of a phone number is trivially reversible by
// enumeration, so it would be the encrypted field's plaintext under a different name.
function digestKey(): string {
  return config.kms.localMasterKey ?? config.keys.wrappingKey ?? 'giam-digest-development-key';
}

export function blindDigest(value: string): string {
  return createHmac('sha256', digestKey()).update(value.trim().toLowerCase()).digest('hex');
}

export function digestMatches(value: string, digest: string): boolean {
  const computed = Buffer.from(blindDigest(value));
  const stored = Buffer.from(digest);
  return computed.length === stored.length && timingSafeEqual(computed, stored);
}
