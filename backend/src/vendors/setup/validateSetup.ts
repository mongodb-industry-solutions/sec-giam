import { Db } from 'mongodb';
import {
  GIAM_COLLECTIONS, scopedCollections, encryptedCollections,
  REALM_COLLECTION, SIGNING_KEY_COLLECTION,
} from '../../shared/models/collections';
import { plannedIndexes } from './createIndexes';
import { assertCryptSharedLib } from '../encryption/qeClient';
import { findOrphanedDeks } from '../encryption/keyVault';
import { buildEncryptedFieldsMaps } from '../encryption/encryptedFieldsMaps';
import { config, keyVaultNamespace } from '../../config';

export interface ValidationResult {
  checks: Array<{ name: string; ok: boolean; detail?: string }>;
  ok: boolean;
}

// The declared encrypted paths, taken from the same builder setup used, so the two cannot disagree by
// being written down twice.
function declaredEncryptedPaths(): Record<string, string[]> {
  const placeholder = null as never;
  const maps = buildEncryptedFieldsMaps({
    identityEmail: placeholder,
    identityPhone: placeholder,
    identityName: placeholder,
    apiKeyHash: placeholder,
  });
  const paths: Record<string, string[]> = {};
  for (const [name, map] of Object.entries(maps)) {
    paths[name] = (map.fields as Array<{ path: string }>).map((f) => f.path).sort();
  }
  return paths;
}

/**
 * Validates the GIAM database.
 *
 * Failures here are cheap. The same problems found at runtime look like a generic 503, a blanket 401
 * or a driver-level message about unsatisfied keys, which is what makes them expensive.
 */
export async function validateSetup(db: Db): Promise<ValidationResult> {
  const checks: ValidationResult['checks'] = [];
  const add = (name: string, ok: boolean, detail?: string) => checks.push({ name, ok, detail });

  try {
    add('crypt_shared library', true, assertCryptSharedLib());
  } catch (err) {
    add('crypt_shared library', false, err instanceof Error ? err.message : String(err));
  }

  const info = await db.listCollections({}, { nameOnly: false }).toArray() as Array<{
    name: string;
    type?: string;
    options?: { encryptedFields?: { fields?: Array<{ path: string }> }; timeseries?: unknown };
  }>;
  const byName = new Map(info.map((c) => [c.name, c]));

  for (const spec of GIAM_COLLECTIONS) {
    add(`collection ${spec.name}`, byName.has(spec.name), byName.has(spec.name) ? undefined : 'missing');
  }

  // The registry is the ownership record. A collection in the database that is absent from it is an
  // undocumented owner, and the mechanical check is what keeps that from being a reviewer's job.
  const known = new Set(GIAM_COLLECTIONS.map((s) => s.name));
  const unregistered = info
    .map((c) => c.name)
    // The storage engine's own: Queryable Encryption's metadata collections and the buckets and view
    // behind a time series. They are not schema anyone owns, and listing them would turn a real
    // ownership check into noise a reader learns to skip.
    .filter((name) => !name.startsWith('enxcol_.') && !name.startsWith('system.'))
    .filter((name) => name !== config.mongodb.keyVaultCollection && !known.has(name));
  add('every collection is registered with an owning module', unregistered.length === 0,
    unregistered.length === 0 ? undefined : `unregistered: ${unregistered.join(', ')}`);

  for (const plan of plannedIndexes()) {
    if (plan.options.name === '_id_') continue;
    if (!byName.has(plan.collection)) {
      add(`index ${plan.collection}.${plan.options.name}`, false, 'collection missing');
      continue;
    }
    const names = (await db.collection(plan.collection).indexes()).map((i) => i.name);
    const ok = names.includes(plan.options.name);
    add(`index ${plan.collection}.${plan.options.name}`, ok, ok ? undefined : 'missing');
  }

  // The encrypted-fields drift check. Setup SKIPS a collection that already exists, so a map changed
  // in code and never applied is silently absent, and nothing at runtime complains: the field is
  // simply stored in clear.
  const declared = declaredEncryptedPaths();
  for (const spec of encryptedCollections()) {
    const actual = (byName.get(spec.name)?.options?.encryptedFields?.fields ?? []).map((f) => f.path).sort();
    const expected = declared[spec.name] ?? [];
    const ok = actual.length > 0 && actual.join(',') === expected.join(',');
    add(`encrypted fields on ${spec.name} match the model`, ok,
      ok ? `${actual.length} field(s)` : `declared [${expected.join(', ')}] but stored [${actual.join(', ')}]; needs --reset`);
  }

  // The time-series collection cannot be converted in place, so getting it wrong once is permanent
  // until the collection is dropped.
  for (const spec of GIAM_COLLECTIONS.filter((s) => s.kind === 'timeseries')) {
    const isTimeseries = Boolean(byName.get(spec.name)?.options?.timeseries) || byName.get(spec.name)?.type === 'timeseries';
    add(`${spec.name} is a time series`, isTimeseries, isTimeseries ? undefined : 'created plain; needs --reset');
  }

  // The vault must be GIAM's own and must hold GIAM's own keys. An empty one means the setup never
  // provisioned them, and every encrypted read would fail on the first request.
  try {
    const dekCount = await db.collection(config.mongodb.keyVaultCollection).countDocuments();
    add(`key vault ${keyVaultNamespace()}`, dekCount > 0, `${dekCount} DEK(s), GIAM's own`);
  } catch (err) {
    add(`key vault ${keyVaultNamespace()}`, false, err instanceof Error ? err.message : String(err));
  }

  try {
    const orphans = await findOrphanedDeks(db.client);
    add('DEK references resolve in the key vault', orphans.length === 0,
      orphans.length === 0 ? undefined : `stale in: ${orphans.join(', ')}; rebuild with setup:db:reset`);
  } catch (err) {
    add('DEK references resolve in the key vault', false, err instanceof Error ? err.message : String(err));
  }

  // The day-one invariant, checked against the data rather than only against the model: a record
  // without the partition pair cannot be found by a tenant-scoped query and is effectively invisible.
  for (const spec of scopedCollections()) {
    if (!byName.has(spec.name) || spec.kind === 'timeseries') continue;
    const total = await db.collection(spec.name).estimatedDocumentCount();
    if (total === 0) continue;
    const unpartitioned = await db.collection(spec.name).countDocuments({
      $or: [{ realmId: { $exists: false } }, { tenantId: { $exists: false } }],
    });
    add(`every ${spec.name} record carries realmId and tenantId`, unpartitioned === 0,
      unpartitioned === 0 ? `${total} record(s)` : `${unpartitioned} of ${total} missing the partition key`);
  }

  // A realm with no published key can neither sign nor be verified, and the failure reads as a token
  // bug rather than an unseeded key set.
  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1, issuer: 1 } })
    .toArray()
    .catch(() => []) as Array<{ realmId?: string; name?: string; issuer?: string }>;
  add('at least one realm is seeded', realms.length > 0, `${realms.length} realm(s)`);
  for (const realm of realms) {
    add(`realm ${realm.name} declares an issuer`, Boolean(realm.issuer), realm.issuer ?? 'missing');
    const keys = await db.collection(SIGNING_KEY_COLLECTION)
      .countDocuments({ realmId: realm.realmId, status: 'active' })
      .catch(() => 0);
    add(`realm ${realm.name} publishes an active signing key`, keys > 0, `${keys} key(s)`);
  }

  return { checks, ok: checks.every((c) => c.ok) };
}
