import type { Binary } from 'mongodb';
import { IDENTITY_COLLECTION, API_KEY_COLLECTION } from '../../shared/models/collections';
import { config } from '../../config';

// What GIAM encrypts at rest, under its OWN DEKs in its OWN vault.
//
// Deliberately narrow. A credential is already a one-way hash, so encrypting it buys nothing while
// blocking the lookup that verifies it. What is encrypted is the personal data an identity record
// holds and the API key hash, which is a bearer secret rather than a digest of a password.
export interface GiamDeks {
  identityEmail: Binary;
  identityPhone: Binary;
  identityName: Binary;
  apiKeyHash: Binary;
}

// Deterministic alt-names, so a reseed finds the existing key instead of minting a second one.
export const DEK_ALT_NAMES = {
  identityEmail: 'DEK-giam-identity-email',
  identityPhone: 'DEK-giam-identity-phone',
  identityName: 'DEK-giam-identity-name',
  apiKeyHash: 'DEK-giam-apikey-hash',
} as const;

/**
 * Equality where a value is looked up by its exact form, substring where an operator searches by a
 * fragment of a name.
 *
 * Email and phone need equality because home-realm discovery and account recovery both resolve a
 * principal FROM the value the user typed; without the index the driver refuses the query outright.
 * The formatted name needs substring because administration searches it by fragment.
 *
 * The queryable values are SCALARS (`primaryEmail`, `primaryPhone`) rather than entries in the SCIM
 * multi-valued arrays, because Queryable Encryption cannot encrypt a field underneath an array. The
 * SCIM `emails[]` and `phoneNumbers[]` representation is projected from these at read time, so the
 * wire contract still matches the standard while the stored value stays encrypted and searchable.
 *
 * substringPreview requires crypt_shared 8.2+ AND server 8.2+. On an older cluster it degrades to
 * equality rather than failing setup, which keeps the field encrypted and exactly searchable instead
 * of trading the whole deployment for one query shape.
 */
export function buildEncryptedFieldsMaps(deks: GiamDeks): Record<string, { fields: unknown[] }> {
  const nameQueries = config.mongodb.textSearch
    ? {
      queryType: 'substringPreview',
      contention: 8,
      // Within the cluster's default substringPreview limits, so setup needs no
      // fleDisableSubstringPreviewParameterLimits override. The server refuses strMaxLength above 60
      // outright, and 30 is what the platform already uses for the equivalent field. A longer
      // formatted name is refused at write time rather than silently truncated.
      strMaxLength: 30,
      strMaxQueryLength: 10,
      strMinQueryLength: 3,
      caseSensitive: false,
      diacriticSensitive: false,
    }
    : { queryType: 'equality', contention: 8 };

  return {
    [IDENTITY_COLLECTION]: {
      fields: [
        { keyId: deks.identityEmail, path: 'primaryEmail', bsonType: 'string', queries: { queryType: 'equality', contention: 8 } },
        { keyId: deks.identityPhone, path: 'primaryPhone', bsonType: 'string', queries: { queryType: 'equality', contention: 8 } },
        { keyId: deks.identityName, path: 'name.formatted', bsonType: 'string', queries: nameQueries },
      ],
    },
    [API_KEY_COLLECTION]: {
      // Equality over ciphertext: a presented key is located by its hash without decrypting the set.
      fields: [
        { keyId: deks.apiKeyHash, path: 'keyHash', bsonType: 'string', queries: { queryType: 'equality', contention: 8 } },
      ],
    },
  };
}
