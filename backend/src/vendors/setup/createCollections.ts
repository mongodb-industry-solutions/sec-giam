import { Db } from 'mongodb';
import { GIAM_COLLECTIONS, SECURITY_EVENT_COLLECTION } from '../../shared/models/collections';
import { buildEncryptedFieldsMaps, GiamDeks } from '../encryption/encryptedFieldsMaps';

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
  if (!existing.has(SECURITY_EVENT_COLLECTION) || reset) {
    console.log(`  note:    ${SECURITY_EVENT_COLLECTION} is a time series; it cannot be converted in place`);
  }
}
