import * as dotenv from 'dotenv';
import { resolve } from 'path';
import { seedRealms } from './seedRealms';
import { seedKeys } from './seedKeys';
import { seedIdentities } from './seedIdentities';
import { seedAuthorization } from './seedAuthorization';
import { seedClients } from './seedClients';
import { REALM_COLLECTION } from '../../shared/models/collections';
import { getQEClient, closeQEClient } from '../encryption/qeClient';
import { config } from '../../config';

dotenv.config({ path: resolve(__dirname, '../../../../../.env') });

// Seeders are idempotent and additive: an existing document is upserted, never clobbered, so a reseed
// over a populated database does not destroy state a demonstration depends on. Identifiers are
// deterministic, which is what lets another service reference one without ever reading this database.
export async function runSeed(): Promise<void> {
  if (!config.mongodb.uri) throw new Error('GIAM_DB_URI / MONGODB_URI is not set');
  const client = await getQEClient();
  try {
    const db = client.db(config.mongodb.dbName);
    console.log(`Seeding the GIAM database "${config.mongodb.dbName}"\n`);
    // Realms first: every other record is partitioned by one, so nothing can be written before them.
    await seedRealms(db);
    // Keys after realms: a key belongs to a realm, and a realm with none can neither sign nor be
    // verified against.
    await seedKeys(db);
    // Principals and their credentials, into the realm the demo population belongs to. Resolved by
    // NAME rather than hardcoded by id, so the seeder carries no identifier of its own.
    await seedIdentities(db);
    // The bank realm population: its staff and one account holder. A separate fixture because a
    // realm is a separate institution, not a section of another one.
    await seedIdentities(db, 'bankIdentities.json', 'bankCredentials.json');
    // Roles and their assignments. After principals, since an assignment names one.
    await seedAuthorization(db);
    await seedAuthorization(db, 'bankRoles.json', 'bankIdentities.json');
    // Clients last: a service identity's role has to exist before it can be assigned.
    await seedClients(db);
    console.log('\nGIAM seed complete.');
  } finally {
    await closeQEClient();
  }
}
