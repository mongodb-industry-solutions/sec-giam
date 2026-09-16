import { Db, UpdateFilter } from 'mongodb';
import { KEY_COLLECTION } from '../../../shared/models/collections';
import { KeyRecord, assertNoPlaintextPrivateKey } from '../models/key.model';
import { SigningKeyStore } from './keyRing.service';

/**
 * The published key set, in the database.
 *
 * The database is the coordination point between replicas and it is already there: no new
 * infrastructure, no shared volume, no key-encryption key to distribute and later lose. What it holds
 * is public material and a lease, never a private key.
 */
export class MongoSigningKeyStore implements SigningKeyStore {
  constructor(private readonly db: Db) {}

  /** The same handle, offered to the ring so publishing a key can leave evidence. */
  get eventDb(): Db {
    return this.db;
  }

  private get collection() {
    return this.db.collection<KeyRecord>(KEY_COLLECTION);
  }

  async upsert(record: KeyRecord): Promise<void> {
    // Checked on the write path as well as in validation: this is the last point at which a private
    // key could reach the database, and after it there is nothing left to catch it.
    assertNoPlaintextPrivateKey(record);
    const { kid, ...rest } = record;
    // The record is authoritative for `notAfter`, so a record without one CLEARS it rather than
    // leaving the stored value behind. A `$set` of the present fields alone let a withdrawal date
    // written by a sweep outlive the republication that undid the sweep: the key signed again and
    // never came back into the published set, which empties the key set while tokens keep being
    // minted. Callers that mean to keep a withdrawal date carry it on the record they pass.
    const update: UpdateFilter<KeyRecord> = { $set: rest, $setOnInsert: { kid } };
    if (rest.notAfter === undefined) update.$unset = { notAfter: '' };
    await this.collection.updateOne({ kid }, update, { upsert: true });
  }

  async findByKid(kid: string): Promise<KeyRecord | null> {
    return this.collection.findOne({ kid }, { projection: { _id: 0 } });
  }

  async listByRealm(realmId: string): Promise<KeyRecord[]> {
    return this.collection.find({ realmId }, { projection: { _id: 0 } }).toArray();
  }

  async renewLease(kid: string, leaseExpiresAt: string): Promise<void> {
    // A renewed lease says the owning replica is alive, which also withdraws the withdrawal: the key
    // is live again, so the date that would take it out of the published set is removed with it.
    await this.collection.updateOne(
      { kid },
      { $set: { leaseExpiresAt, signingEligible: true }, $unset: { notAfter: '' } },
    );
  }

  async markIneligible(kid: string, notAfter: string): Promise<void> {
    await this.collection.updateOne({ kid }, { $set: { signingEligible: false, notAfter } });
  }
}
