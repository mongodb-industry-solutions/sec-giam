import type { Binary } from 'mongodb';
import { PRINCIPAL_COLLECTION } from '../../shared/models/collections';
import { capabilities } from '../mongodb/deployment';

// What GIAM encrypts at rest, under its OWN DEKs in its OWN vault.
//
// Deliberately narrow: the personal data a principal record holds, and nothing else.
//
// v40 P3.3 DROPPED Queryable Encryption over the API key hash. Two reasons, and the second is the
// one that decided it. It encrypted a one-way hash, which buys no confidentiality that the hash did
// not already provide. And the API key merged into `credential`, so keeping the entry would have
// made `credential` an encrypted collection: every client authentication would then carry
// ESC/ECOC state on what is now one of the hottest lookups in the system, in exchange for
// encrypting a digest. A credential is verified rather than looked up, so nothing is lost.
export interface GiamDeks {
  identityEmail: Binary;
  identityPhone: Binary;
  identityName: Binary;
}

// Deterministic alt-names, so a reseed finds the existing key instead of minting a second one.
export const DEK_ALT_NAMES = {
  identityEmail: 'DEK-giam-identity-email',
  identityPhone: 'DEK-giam-identity-phone',
  identityName: 'DEK-giam-identity-name',
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
 * The substring query type comes from the resolved QE text-search profile
 * (`@leafypay/mongo-compat`'s `resolveQeProfile`), which names it `substringPreview` on an 8.2-8.3
 * server and `substring` on 9.0+ - the two spellings are mutually exclusive, and a collection
 * carrying the wrong one fails EVERY encrypted query on it, including the plain equality lookups
 * on the other two fields.
 *
 * On a cluster below 8.2 (or Community, which cannot analyse an encrypted query at all) the field
 * degrades to equality rather than failing setup, which keeps it encrypted and exactly searchable
 * instead of trading the whole deployment for one query shape.
 *
 * That degradation is decided in two places, and either one is enough:
 *   1. the DEPLOYMENT cannot do it (MONGODB_TYPE / MONGODB_VERSION say below 8.2, or Community).
 *      Known before a connection exists;
 *   2. the DRIVER refuses the query type at create time, which `createCollections` catches and
 *      rebuilds the map with `forceEquality`. The last-resort net, for a crypt_shared that does not
 *      match the server it points at.
 *
 * (1) is what a hand-managed flag used to stand in for, badly: it CLAIMED the capability, so a
 * deployment that declared it on an older cluster failed setup with `principal` left uncreated
 * instead of degrading. There is no switch for this any more, and so nothing to set wrongly.
 */
export function buildEncryptedFieldsMaps(
  deks: GiamDeks,
  options: { forceEquality?: boolean } = {},
): Record<string, { fields: unknown[] }> {
  const profile = capabilities().qeTextSearchProfile;
  const nameQueries = profile.textSearch && !options.forceEquality
    ? {
      queryType: profile.substring,
      contention: 8,
      // Within the cluster's default substring limits (10 on 8.2-8.3, 6 on 9.0+), so setup needs
      // no parameter-limit override. The server refuses strMaxLength above 60 outright, and 30 is
      // what the platform already uses for the equivalent field. A longer formatted name is
      // refused at write time rather than silently truncated.
      strMaxLength: 30,
      strMaxQueryLength: profile.substringMaxQueryLength,
      strMinQueryLength: 3,
      caseSensitive: false,
      diacriticSensitive: false,
    }
    : { queryType: 'equality', contention: 8 };

  return {
    [PRINCIPAL_COLLECTION]: {
      fields: [
        { keyId: deks.identityEmail, path: 'primaryEmail', bsonType: 'string', queries: { queryType: 'equality', contention: 8 } },
        { keyId: deks.identityPhone, path: 'primaryPhone', bsonType: 'string', queries: { queryType: 'equality', contention: 8 } },
        { keyId: deks.identityName, path: 'name.formatted', bsonType: 'string', queries: nameQueries },
      ],
    },
  };
}
