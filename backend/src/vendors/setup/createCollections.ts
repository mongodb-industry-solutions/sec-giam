import { Db } from 'mongodb';
import { GIAM_COLLECTIONS, AUDIT_COLLECTION } from '../../shared/models/collections';
import { buildEncryptedFieldsMaps, GiamDeks } from '../encryption/encryptedFieldsMaps';
import { config } from '../../config';

/**
 * Creates every collection from the canonical registry.
 *
 * Driven by the registry rather than by a list here, so a collection cannot exist in the database
 * without an owning module recorded next to it.
 *
 * Note the trap this project has paid for before: setup SKIPS a collection that already exists, so a
 * collection created once with the wrong encryptedFields keeps them until it is dropped. Changing an
 * encrypted-fields map needs `--reset`, and the runbook says so.
 */
export async function createCollections(db: Db, deks: GiamDeks, reset = false): Promise<void> {
  const existing = new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));
  const maps = buildEncryptedFieldsMaps(deks);

  /**
   * On `--reset`, drop collections the registry NO LONGER NAMES as well as the ones it does.
   *
   * Without this the loop below only ever touches registered collections, so a collection the model
   * has dropped or renamed away survives every reset forever. That is not a cosmetic leftover: its
   * `encryptedFields` still reference DEKs the rebuilt vault no longer holds, so validation reports
   * a stale DEK on a collection nothing reads, and "rebuild with --reset" does not fix it because
   * the reset is exactly what skips it.
   *
   * Guarded to `reset`, so an ordinary setup run never removes anything.
   */
  if (reset) {
    const registered = new Set<string>(GIAM_COLLECTIONS.map((spec) => spec.name));
    for (const name of existing) {
      if (registered.has(name)) continue;
      // The driver's own encrypted-state collections go with their parent, not on their own.
      if (name.startsWith('enxcol_.')) continue;
      // The server's own namespaces, including the view a time series collection creates. Dropping
      // one is not permitted and is not ours to attempt.
      if (name.startsWith('system.')) continue;
      if (name === config.mongodb.keyVaultCollection) continue;
      await db.collection(name).drop();
      existing.delete(name);
      console.log(`  dropped: ${name} (the model no longer names it)`);
    }
  }

  for (const spec of GIAM_COLLECTIONS) {
    if (existing.has(spec.name) && !reset) {
      const note = spec.encrypted ? ' (already exists; encryptedFields changes need --reset)' : ' (already exists)';
      console.log(`  skip:    ${spec.name}${note}`);
      continue;
    }
    if (existing.has(spec.name)) {
      await db.collection(spec.name).drop();
      console.log(`  dropped: ${spec.name}`);
    }

    if (spec.kind === 'timeseries') {
      // Append-only, high volume, queried by range. Seconds granularity: security events arrive in
      // bursts around a sign-in, and a coarser bucket would put a whole login flow in one document.
      await db.createCollection(spec.name, {
        timeseries: { timeField: 'ts', metaField: 'meta', granularity: 'seconds' },
      });
      console.log(`  created: ${spec.name} (time series) (${spec.purpose})`);
      continue;
    }

    if (spec.encrypted) {
      await db.createCollection(spec.name, { encryptedFields: maps[spec.name] as never });
      console.log(`  created: ${spec.name} (QE) (${spec.purpose})`);
      continue;
    }

    await db.createCollection(spec.name);
    console.log(`  created: ${spec.name} (${spec.purpose})`);
  }

  // Stated rather than assumed: the audit collection is the one that must never be created plain, or
  // a range query over it would work and a reviewer would never learn it is not a time series.
  if (!existing.has(AUDIT_COLLECTION) || reset) {
    console.log(`  note:    ${AUDIT_COLLECTION} is a time series; it cannot be converted in place`);
  }
}
