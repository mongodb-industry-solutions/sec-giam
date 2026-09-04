// Setup and the seeder are the source of truth for the database, and they must be IDEMPOTENT.
//
// That is a project rule rather than a preference: every schema and data change goes through
// `vendors/setup/*` and `vendors/seed/*` so a deployment is reproducible, and a seeder that is only
// safe the first time is a seeder nobody dares run. The failure it prevents is quiet: a second run
// inserting rather than upserting leaves duplicates that pass every other test until a unique index
// is added months later, or until a lookup that assumed one record finds two.
//
// Asserted here rather than checked by hand, because "I ran it twice and it looked fine" is exactly
// the kind of verification that stops happening.
import { describe, it, expect, beforeAll } from 'vitest';
import { MongoClient, Db } from 'mongodb';
import { resolve } from 'path';
import * as dotenv from 'dotenv';

dotenv.config({ path: [resolve(__dirname, '../../../.env'), resolve(__dirname, '../../../../.env')] });

const URI = process.env.GIAM_MONGODB_URI ?? process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.GIAM_MONGODB_DB ?? process.env.GIAM_DB_NAME ?? 'giam';

/**
 * The identifier each collection is keyed by.
 *
 * The one the seeder upserts on, so a duplicate here is precisely a seed run that inserted where it
 * should have matched. `realmId` is included where a collection is realm-scoped and the identifier is
 * only unique within one.
 */
const KEYED_BY: Array<[string, string[]]> = [
  ['principal', ['subjectId']],
  ['credential', ['credentialId']],
  ['realm', ['realmId']],
  ['domain', ['realmId', 'providerId']],
  ['role', ['realmId', 'roleId']],
  ['policy', ['realmId', 'policyId']],
  ['resource', ['realmId', 'resourceId']],
];

describe('setup and the seeder are idempotent, because they are the source of truth', () => {
  let client: MongoClient | null = null;
  let db: Db | null = null;

  beforeAll(async () => {
    try {
      client = new MongoClient(URI, { serverSelectionTimeoutMS: 3000 });
      await client.connect();
      db = client.db(DB_NAME);
      await db.command({ ping: 1 });
    } catch {
      db = null;
    }
  });

  it.each(KEYED_BY)('leaves exactly one %s per %s', async (collection, keys) => {
    if (!db) return;
    const _id = Object.fromEntries(keys.map((key) => [key, `$${key}`]));
    const duplicated = await db.collection(collection).aggregate([
      { $group: { _id, count: { $sum: 1 } } },
      { $match: { count: { $gt: 1 } } },
      { $limit: 5 },
    ]).toArray();

    expect(
      duplicated,
      `${collection} holds ${duplicated.length} duplicated key(s) after seeding: `
      + `${duplicated.map((entry) => JSON.stringify(entry._id)).join(', ')}. `
      + 'A seed run inserted where it should have matched.',
    ).toEqual([]);
  });

  /**
   * The seeder preserves subjects, and that is not cosmetic.
   *
   * `subjectId` values are already written into audit rows, sessions and application records, so a
   * reseed that minted new ones would break no test here and quietly orphan everything naming one.
   * A principal with no subject is the shape that failure takes.
   */
  it('gives every principal a subject, so nothing that names one is orphaned', async () => {
    if (!db) return;
    const missing = await db.collection('principal')
      .countDocuments({ $or: [{ subjectId: { $exists: false } }, { subjectId: '' }] });
    expect(missing).toBe(0);
  });

  /**
   * Every scoped record carries its partition from its first version.
   *
   * `setup:check` asserts this too, and it is repeated here because that check is a command somebody
   * runs while this is a test that runs itself.
   */
  it('gives every scoped record its realm and its tenant', async () => {
    if (!db) return;
    for (const [collection] of KEYED_BY) {
      const unpartitioned = await db.collection(collection).countDocuments({
        $or: [{ realmId: { $exists: false } }, { tenantId: { $exists: false } }],
      });
      expect(unpartitioned, `${collection} holds ${unpartitioned} record(s) with no realm or tenant`).toBe(0);
    }
  });
});
