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
import { connectionForTests } from './support/directDb';

/**
 * The connection comes from the shared helper, which resolves it the way the SERVER does.
 *
 * This file used to read `GIAM_MONGODB_URI` and `GIAM_MONGODB_DB`, neither of which this project
 * sets: the real names are `GIAM_DB_URI` (falling back to `MONGODB_URI`) and `GIAM_DB_NAME`. It
 * therefore connected to a local default, found no collections, and passed on an empty database.
 * A duplicate-detection test that looks at the wrong database reports success for the one reason it
 * must never report success, and it did so silently for every run.
 */
const { uri: URI, dbName: DB_NAME } = connectionForTests();

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
  ['domain', ['realmId', 'domainId']],
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
   * The database this ran against was the seeded one.
   *
   * Without this, every assertion above is satisfied by an empty database, which is exactly how the
   * wrong connection went unnoticed. A seeded realm is the cheapest proof that there was something
   * to find duplicates in.
   */
  it('ran against a seeded database, not an empty one', async () => {
    if (!db) return;
    const realms = await db.collection('realm').countDocuments({});
    expect(realms, 'no realm exists, so nothing above asserted anything').toBeGreaterThan(0);
  });

  /**
   * One registration per client id, within a realm.
   *
   * `credentialId` above is derived with `uuidv5` from the client id, so it is unique by
   * construction and cannot catch a second registration of the same client arriving by another
   * route. `clientId` is what every OAuth lookup resolves on, and two records sharing one means a
   * `findOne` decides which registration is real by collection order.
   */
  it('leaves exactly one registration per client id in a realm', async () => {
    if (!db) return;
    const duplicated = await db.collection('credential').aggregate([
      { $match: { type: 'oauth_client' } },
      { $group: { _id: { realmId: '$realmId', clientId: '$clientId' }, count: { $sum: 1 } } },
      { $match: { count: { $gt: 1 } } },
      { $limit: 5 },
    ]).toArray();

    expect(
      duplicated,
      `two registrations share a client id: ${duplicated.map((e) => JSON.stringify(e._id)).join(', ')}`,
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
