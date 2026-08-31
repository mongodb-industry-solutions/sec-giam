import { Db } from 'mongodb';
import { REALM_COLLECTION } from '../../shared/models/collections';
import { RealmRecord } from '../../modules/realm/models/realm.model';
import { KeyRing } from '../../modules/keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../modules/keys/services/signingKeyStore';
import { registerBuiltinPorts } from '../../shared/ports/builtins';
import { keyProviders } from '../../shared/ports';
import { config } from '../../config';

/**
 * Publishes this instance's signing key into every realm's key set.
 *
 * A realm with no published key can neither sign a token nor have one verified, and the failure reads
 * as a token bug rather than as an unseeded key set, so it is seeded rather than left for first use.
 *
 * This is a normal runtime operation, not a seed-only one: exactly the same call runs when a replica
 * starts. Seeding it here just means a freshly built database is usable immediately, and running it
 * twice adds nothing, because the key id is derived from the key itself.
 */
export async function seedKeys(db: Db): Promise<void> {
  registerBuiltinPorts();
  const provider = keyProviders.resolve(config.keys.provider);
  const ring = new KeyRing(new MongoSigningKeyStore(db), provider);

  const realms = await db.collection<RealmRecord>(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1, tenantId: 1 } })
    .toArray();

  for (const realm of realms) {
    // Per realm, because a realm is a KEY boundary: the two sign with different keys published at
    // different key sets, and that is the mechanism that makes a token from one realm useless in
    // the other rather than merely unwelcome.
    const kid = await ring.publishOwnKey(realm.realmId, realm.tenantId);
    console.log(`  key:      ${realm.name} kid=${kid.slice(0, 16)}... (${provider.name})`);
  }
}
