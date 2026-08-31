import { Db } from 'mongodb';
import { SIGNING_KEY_COLLECTION } from '../../../shared/models/collections';
import { SigningKeyRecord, assertNoPlaintextPrivateKey } from '../models/signingKey.model';
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

  private get collection() {
    return this.db.collection<SigningKeyRecord>(SIGNING_KEY_COLLECTION);
  }

  async upsert(record: SigningKeyRecord): Promise<void> {
    // Checked on the write path as well as in validation: this is the last point at which a private
    // key could reach the database, and after it there is nothing left to catch it.
    assertNoPlaintextPrivateKey(record);
    const { kid, ...rest } = record;
    await this.collection.updateOne({ kid }, { $set: rest, $setOnInsert: { kid } }, { upsert: true });
  }

  async findByKid(kid: string): Promise<SigningKeyRecord | null> {
    return this.collection.findOne({ kid }, { projection: { _id: 0 } });
  }

  async listByRealm(realmId: string): Promise<SigningKeyRecord[]> {
    return this.collection.find({ realmId }, { projection: { _id: 0 } }).toArray();
  }

  async renewLease(kid: string, leaseExpiresAt: string): Promise<void> {
    await this.collection.updateOne({ kid }, { $set: { leaseExpiresAt, signingEligible: true } });
  }

  async markIneligible(kid: string, notAfter: string): Promise<void> {
    await this.collection.updateOne({ kid }, { $set: { signingEligible: false, notAfter } });
  }
}
