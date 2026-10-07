import { Db } from 'mongodb';
import {
  GIAM_COLLECTIONS, scopedCollections, encryptedCollections, collectionsWithRetiredFields,
  REALM_COLLECTION, KEY_COLLECTION,
} from '../../shared/models/collections';
import { plannedIndexes, classifyIndex, reconcilable, ExistingIndex } from './createIndexes';
import { assertCryptSharedLib } from '../encryption/qeClient';
import { findOrphanedDeks } from '../encryption/keyVault';
import { buildEncryptedFieldsMaps } from '../encryption/encryptedFieldsMaps';
import { detectDeployment, deployment, capabilities, describeDeployment } from '../mongodb/deployment';
import { config, keyVaultNamespace, realmIssuer } from '../../config';

// warning: converges on the next setup and seed. error: rerun setup. reset: only a rebuild fixes it.
export type CheckSeverity = 'warning' | 'error' | 'reset';

export type SetupVerdict = 'converged' | 'converged-with-warnings' | 'not-converged' | 'requires-reset';

export interface ValidationCheck {
  name: string;
  ok: boolean;
  detail?: string;
  severity?: CheckSeverity;
}

export interface ValidationResult {
  checks: ValidationCheck[];
  ok: boolean;
  verdict: SetupVerdict;
  /** The failures that no amount of re-running setup can fix, in operator words. */
  resetReasons: string[];
}

export function verdictOf(checks: ValidationCheck[]): SetupVerdict {
  const failed = checks.filter((check) => !check.ok);
  if (failed.some((check) => check.severity === 'reset')) return 'requires-reset';
  if (failed.length === 0) return 'converged';
  if (failed.some((check) => check.severity !== 'warning')) return 'not-converged';
  return 'converged-with-warnings';
}

// The declared encrypted paths, taken from the same builder setup used, so the two cannot disagree by
// being written down twice.
function declaredEncryptedPaths(): Record<string, string[]> {
  const placeholder = null as never;
  const maps = buildEncryptedFieldsMaps({
    identityEmail: placeholder,
    identityPhone: placeholder,
    identityName: placeholder,
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
  const checks: ValidationCheck[] = [];
  const add = (name: string, ok: boolean, detail?: string, severity: CheckSeverity = 'error') =>
    checks.push({ name, ok, detail, severity });

  try {
    add('crypt_shared library', true, assertCryptSharedLib());
  } catch (err) {
    add('crypt_shared library', false, err instanceof Error ? err.message : String(err));
  }

  /**
   * The deployment itself, checked before its contents.
   *
   * Probed here rather than trusted from the environment: validation exists to find the problems
   * that otherwise surface as a 503, and a declared version that does not match the cluster is one
   * of them. `error` and not `reset` for the mismatch, since correcting the environment fixes it;
   * an edition that cannot encrypt at all is a `reset`, because nothing about this database can be
   * made right while it stays where it is.
   */
  await detectDeployment(db.client);
  const current = deployment();
  const caps = capabilities();
  add('deployment supports automatic Queryable Encryption', caps.automaticEncryption,
    describeDeployment(current)
      + (caps.automaticEncryption ? '' : ': encrypted reads cannot work here. Atlas or Enterprise 7.0+ is required'),
    'reset');
  add('the declared deployment matches the cluster', !current.mismatch, current.mismatch, 'error');
  add('substring search on encrypted names', caps.qeSubstring,
    caps.qeSubstring
      ? 'available'
      : `needs server 9.0+ (this is ${current.version.raw}); names are stored with equality only`,
    'warning');
  add('change streams are available', caps.changeStreams,
    caps.changeStreams
      ? undefined
      : 'no replica set: the live-session cache cannot start. Revocation still holds through the '
        + 'authoritative read and the token lifetime',
    'warning');

  const info = await db.listCollections({}, { nameOnly: false }).toArray() as Array<{
    name: string;
    type?: string;
    options?: { encryptedFields?: { fields?: Array<{ path: string }> }; timeseries?: unknown };
  }>;
  const byName = new Map(info.map((c) => [c.name, c]));

  // The inventory, with what each holds. A collection that exists and is empty and a collection that
  // is missing fail in very different ways, and reporting only presence leaves a reader unable to tell
  // "never seeded" from "seeded and wrong".
  for (const spec of GIAM_COLLECTIONS) {
    if (!byName.has(spec.name)) {
      add(`collection ${spec.name}`, false, 'missing');
      continue;
    }
    const count = await db.collection(spec.name).estimatedDocumentCount().catch(() => -1);
    add(`collection ${spec.name}`, true, count < 0 ? 'present, count unavailable' : `${count} document(s)`);
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
  // A warning, not an error: reconciliation never drops a collection, so this is somebody's decision.
  add('every collection is registered with an owning module', unregistered.length === 0,
    unregistered.length === 0 ? undefined : `unregistered: ${unregistered.join(', ')}`, 'warning');

  const plans = plannedIndexes();
  for (const plan of plans) {
    if (plan.options.name === '_id_') continue;
    if (!byName.has(plan.collection)) {
      add(`index ${plan.collection}.${plan.options.name}`, false, 'collection missing');
      continue;
    }
    const names = (await db.collection(plan.collection).indexes()).map((i) => i.name);
    const ok = names.includes(plan.options.name);
    add(`index ${plan.collection}.${plan.options.name}`, ok, ok ? undefined : 'missing');
  }

  // The other direction: an index the database has and the plan does not, which a rename leaves behind.
  const plannedByCollection = new Map<string, Set<string>>();
  for (const plan of plans) {
    const set = plannedByCollection.get(plan.collection) ?? new Set<string>();
    set.add(plan.options.name);
    plannedByCollection.set(plan.collection, set);
  }
  for (const [collection, plannedNames] of plannedByCollection) {
    if (!byName.has(collection) || !reconcilable(collection)) continue;
    const indexes = await db.collection(collection).indexes().catch(() => []) as ExistingIndex[];
    const obsolete: string[] = [];
    const unknown: string[] = [];
    for (const index of indexes) {
      const verdict = classifyIndex(index, plannedNames, true);
      if (verdict === 'obsolete') obsolete.push(index.name ?? '(unnamed)');
      if (verdict === 'unrecognised') unknown.push(index.name ?? '(unnamed)');
    }
    add(`${collection} carries no index the model dropped`, obsolete.length === 0,
      obsolete.length === 0 ? undefined : `obsolete: ${obsolete.join(', ')}; setup:db removes them`, 'warning');
    // Reported, never removed: one of these could be an index something else relies on. A
    // driver-managed one is not listed, since it is present by design on every healthy database.
    if (unknown.length > 0) {
      add(`${collection} has indexes nobody can account for`, false,
        `left alone: ${unknown.join(', ')}`, 'warning');
    }
  }

  // Fields a model retired that survive in documents. The seed step unsets them.
  for (const spec of collectionsWithRetiredFields()) {
    if (!byName.has(spec.name)) continue;
    const fields = spec.retiredFields ?? [];
    const surviving = await db.collection(spec.name).countDocuments({
      $or: fields.map((field) => ({ [field]: { $exists: true } })),
    }).catch(() => 0);
    add(`${spec.name} holds no field the model retired`, surviving === 0,
      surviving === 0
        ? `${fields.join(', ')} absent`
        : `${surviving} document(s) still hold ${fields.join(', ')}; setup:seed removes them`,
      'warning');
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
      ok
        ? `${actual.length} field(s)`
        : `declared [${expected.join(', ')}] but stored [${actual.join(', ')}]. `
          + 'An existing collection cannot have its encrypted fields changed, so setup SKIPS it: '
          + 'running setup:db again will never fix this. Rebuild with setup:db:reset, then setup:seed.',
      'reset');
  }

  // The time-series collection cannot be converted in place, so getting it wrong once is permanent
  // until the collection is dropped.
  for (const spec of GIAM_COLLECTIONS.filter((s) => s.kind === 'timeseries')) {
    const isTimeseries = Boolean(byName.get(spec.name)?.options?.timeseries) || byName.get(spec.name)?.type === 'timeseries';
    add(`${spec.name} is a time series`, isTimeseries, isTimeseries
      ? undefined
      : 'created as a plain collection. A collection cannot be converted in place, so re-running '
        + 'setup:db will never fix this. Rebuild with setup:db:reset, then setup:seed.',
    'reset');
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
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray()
    .catch(() => []) as Array<{ realmId?: string; name?: string }>;
  add('at least one realm is seeded', realms.length > 0, `${realms.length} realm(s)`);
  for (const realm of realms) {
    add(`realm ${realm.name} issues under a composable issuer`, Boolean(realm.name), realmIssuer(String(realm.name)));
    const keys = await db.collection(KEY_COLLECTION)
      .countDocuments({ realmId: realm.realmId, status: 'active' })
      .catch(() => 0);
    add(`realm ${realm.name} publishes an active signing key`, keys > 0, `${keys} key(s)`);
  }

  // Warnings do not fail the run: an operator who can never reach green stops reading the result.
  const ok = checks.every((c) => c.ok || c.severity === 'warning');
  const resetReasons = checks
    .filter((c) => !c.ok && c.severity === 'reset')
    .map((c) => `${c.name}: ${c.detail ?? 'cannot converge'}`);
  return { checks, ok, verdict: verdictOf(checks), resetReasons };
}
