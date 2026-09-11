import { MongoClient, Db } from 'mongodb';
import { resolve } from 'path';
import * as dotenv from 'dotenv';

// `backend/.env` included: it is where the authority's own connection lives (see backend/env.example),
// and cleaning up in the wrong database is the same as not cleaning up at all.
dotenv.config({
  path: [
    resolve(__dirname, '../../../.env'),
    resolve(__dirname, '../../../../.env'),
    resolve(__dirname, '../../../../backend/.env'),
  ],
});

/**
 * Resolved exactly the way `backend/src/config.ts` resolves it, names and defaults alike.
 *
 * A test helper that reads a DIFFERENT variable than the server does is the worst kind of wrong
 * here: it connects successfully, to the wrong database, deletes nothing, and reports success. The
 * leak it was written to prevent then goes on happening with a cleanup step that looks like it ran.
 */
const URI = process.env.GIAM_DB_URI ?? process.env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.GIAM_DB_NAME ?? 'giamdb';

/**
 * Direct database access, for the ONE thing a test still needs it for: cleaning up what it created
 * when there is no API to undo it with. Deleting a whole realm, or a principal outright, is not a
 * capability this authority exposes over HTTP, on purpose, so a test that provisions one has no
 * public route to retire it through.
 *
 * Setup and the seeder are still the only source of truth for what the database is SEEDED with;
 * this exists so a test's OWN writes do not linger and get mistaken for some. A test that leaves a
 * realm or a principal behind on every run is not flaky, it is a leak, and a leak that only shows up
 * after enough runs to notice is worse than one that shows up on the first.
 */
export async function withDirectDb<T>(run: (db: Db) => Promise<T>): Promise<T> {
  const client = new MongoClient(URI, { serverSelectionTimeoutMS: 3000 });
  try {
    await client.connect();
    return await run(client.db(DB_NAME));
  } finally {
    await client.close();
  }
}

/** Every collection scoped by `realmId`, so retiring a realm this way retires all of it. */
const REALM_SCOPED_COLLECTIONS = [
  'domain', 'resource', 'role', 'policy', 'principal', 'credential', 'session', 'grant', 'ticket', 'audit', 'key',
];

/** Deletes a realm this authority created for a test, and everything scoped to it. */
export async function deleteTestRealm(realmId: string): Promise<void> {
  await withDirectDb(async (db) => {
    for (const collection of REALM_SCOPED_COLLECTIONS) {
      await db.collection(collection).deleteMany({ realmId });
    }
    await db.collection('realm').deleteOne({ realmId });
  });
}

/** Deletes a principal this authority created for a test, and what references its `subjectId`. */
export async function deleteTestPrincipal(subjectId: string): Promise<void> {
  await withDirectDb(async (db) => {
    for (const collection of ['credential', 'session', 'grant', 'ticket']) {
      await db.collection(collection).deleteMany({ subjectId });
    }
    await db.collection('principal').deleteOne({ subjectId });
  });
}
