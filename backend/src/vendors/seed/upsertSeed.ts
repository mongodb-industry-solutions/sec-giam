import { Collection, Document, Filter, OptionalUnlessRequiredId } from 'mongodb';
import { Meta, newMeta, touchMeta } from '../../shared/models/base.model';

/**
 * The one way a seeder writes a record.
 *
 * Seeders are idempotent and ADDITIVE: an existing document is updated in the fields the fixture owns
 * and left alone everywhere else, so a reseed over a populated database never destroys state a
 * demonstration depends on.
 *
 * It reads before writing, which looks wasteful and is not. Two reasons:
 *
 * - A blind upsert cannot both initialise `meta` on insert and touch `meta.lastModified` on update,
 *   because MongoDB refuses an update that writes `meta` and `meta.lastModified` in one operation.
 * - `meta.version` is what an ETag is derived from. Bumping it on every reseed, including one that
 *   writes identical values, would invalidate every cached representation for no change at all.
 *
 * So a reseed that changes nothing writes nothing, and the version only moves when the record does.
 */
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
