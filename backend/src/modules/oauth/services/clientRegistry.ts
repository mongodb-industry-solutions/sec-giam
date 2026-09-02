import { Db, Filter } from 'mongodb';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { CredentialRecord } from '../../directory/models/credential.model';

/**
 * Where each OAuth client field actually lives on the credential that stores it.
 *
 * This exists because a MongoDB field path is a STRING, and TypeScript checks none of it. A filter
 * naming `clientName` against a collection that stores `metadata.clientName` compiles, typechecks,
 * runs, and quietly matches nothing. That is the worst failure shape available here: a registration
 * lookup that returns empty reads exactly like a client that does not exist.
 *
 * So every path is declared once, here, and every query goes through the translators below. No call
 * site spells a path itself, and the map is unit tested against the model rather than trusted.
 */

/** Fields that stay first class on the credential, under the same name. */
const FIRST_CLASS = new Set([
  'realmId', 'tenantId', 'clientId', 'status', 'credentialId', 'type',
  'ownerId', 'domainId', 'createdAt', 'lastUsedAt', 'expiresAt', 'meta',
]);

/** Fields renamed on the way in, because the credential already had its own name for them. */
const RENAMED: Record<string, string> = {
  clientSecretHash: 'hash',
  clientSecretPrefix: 'secretPrefix',
  // A set of administrators, which is not the same thing as the principal the credential acts as.
  owners: 'administrators',
};

/** Everything else an OAuth client declares lives in the type-specific metadata sub document. */
const METADATA_FIELDS = new Set([
  'clientName', 'clientType', 'redirectUris', 'postLogoutRedirectUris', 'grantTypes',
  'requirePkce', 'tokenEndpointAuthMethod', 'applicationType', 'tokenPolicy',
  'logoUri', 'clientUri', 'demoRoster', 'firstParty', 'backchannel', 'mtls', 'claimMappings',
  'provisioning',
]);

const LOGICAL = new Set(['$and', '$or', '$nor']);

/** The stored path for one flat client field, or null when the field is not a client field. */
export function credentialPath(field: string): string | null {
  if (field.startsWith('meta.')) return field;
  if (FIRST_CLASS.has(field)) return field;
  if (RENAMED[field]) return RENAMED[field];
  if (METADATA_FIELDS.has(field)) return `metadata.${field}`;
  // `scope` is space-delimited on the wire and an array in storage, so it has no single path and
  // must go through `clientUpdate`, which converts the value as well as the name.
  if (field === 'scope') return null;
  return null;
}

/**
 * Translates a filter written in flat client fields into one the credential collection answers.
 *
 * Recursive, because the caller composes with `$or` and `$nor` and a translation that only handled
 * the top level would silently leave the nested halves pointing at paths that do not exist.
 *
 * Always narrows to `type: 'oauth_client'`. Without that a password credential could answer a
 * client lookup, which is the kind of confusion that only shows up as a very strange bug report.
 */
export function clientFilter(flat: Record<string, unknown>): Filter<CredentialRecord> {
  const translated: Record<string, unknown> = {};

  for (const [field, value] of Object.entries(flat)) {
    if (LOGICAL.has(field)) {
      translated[field] = (value as Array<Record<string, unknown>>).map(
        (clause) => clientFilterClause(clause),
      );
      continue;
    }
    if (field === '$not') {
      translated[field] = clientFilterClause(value as Record<string, unknown>);
      continue;
    }
    const path = credentialPath(field);
    if (!path) throw new Error(`no credential path for client field "${field}"`);
    translated[path] = value;
  }

  return { ...translated, type: 'oauth_client' } as Filter<CredentialRecord>;
}

/** A nested clause: translated the same way, but without re-asserting the type discriminator. */
function clientFilterClause(clause: Record<string, unknown>): Record<string, unknown> {
  const translated: Record<string, unknown> = {};
  for (const [field, value] of Object.entries(clause)) {
    if (LOGICAL.has(field)) {
      translated[field] = (value as Array<Record<string, unknown>>).map(clientFilterClause);
      continue;
    }
    if (field === '$not') {
      translated[field] = clientFilterClause(value as Record<string, unknown>);
      continue;
    }
    const path = credentialPath(field);
    if (!path) throw new Error(`no credential path for client field "${field}"`);
    translated[path] = value;
  }
  return translated;
}

/**
 * Translates a `$set` written in flat client fields, converting values where the shape differs.
 *
 * `scope` is the one field where the wire form and the stored form genuinely differ: RFC 7591 says
 * space-delimited, and an array is what a query can reason about. Converting it here rather than at
 * the call site is what keeps the two representations from drifting apart.
 */
export function clientUpdate(flat: Record<string, unknown>): Record<string, unknown> {
  const translated: Record<string, unknown> = {};
  for (const [field, value] of Object.entries(flat)) {
    if (field === 'scope') {
      translated['metadata.scopes'] = typeof value === 'string'
        ? value.split(' ').filter(Boolean)
        : value;
      continue;
    }
    const path = credentialPath(field);
    if (!path) throw new Error(`no credential path for client field "${field}"`);
    translated[path] = value;
  }
  return translated;
}

/** The credential collection, typed. Named for what the caller is asking about. */
export function clientCredentials(db: Db) {
  return db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
}
