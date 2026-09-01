import { Collection, Db, Document, Filter, OptionalUnlessRequiredId } from 'mongodb';
import { Meta, newMeta, touchMeta } from '../../shared/models/base.model';
import { collectionsWithRetiredFields } from '../../shared/models/collections';

// The one way a seeder writes a record: idempotent, and only in the fields the fixture owns.
// It reads first because `meta` cannot be initialised and touched in one update, and because
// `meta.version` backs an ETag: a reseed that changes nothing must write nothing.
export interface SeedOutcome {
  action: 'created' | 'updated' | 'unchanged';
}

export async function upsertSeed<T extends Document & { meta: Meta }>(
  collection: Collection<T>,
  filter: Filter<T>,
  owned: Partial<T>,
  onInsert: Partial<T>,
  resourceType?: string,
): Promise<SeedOutcome> {
  const existing = await collection.findOne(filter);

  if (!existing) {
    await collection.insertOne({
      ...onInsert,
      ...owned,
      meta: newMeta(resourceType),
    } as OptionalUnlessRequiredId<T>);
    return { action: 'created' };
  }

  const changed = Object.entries(owned).filter(([key, value]) => {
    const current = (existing as Document)[key];
    return JSON.stringify(current) !== JSON.stringify(value);
  });
  if (changed.length === 0) return { action: 'unchanged' };

  await collection.updateOne(filter, {
    $set: { ...Object.fromEntries(changed), meta: touchMeta(existing.meta) },
  } as never);
  return { action: 'updated' };
}

// Unsets only the fields a model DECLARES retired: no document is deleted, no other field is touched.
export async function retireDeclaredFields(db: Db): Promise<void> {
  const existing = new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));

  for (const spec of collectionsWithRetiredFields()) {
    if (!existing.has(spec.name)) continue;
    const fields = spec.retiredFields ?? [];
    const filter = { $or: fields.map((field) => ({ [field]: { $exists: true } })) };
    const affected = await db.collection(spec.name).countDocuments(filter);
    if (affected === 0) continue;
    await db.collection(spec.name).updateMany(filter, {
      $unset: Object.fromEntries(fields.map((field) => [field, ''])),
    });
    console.log(`  retired: ${spec.name}.${fields.join(', ')} removed from ${affected} document(s)`);
  }
}
