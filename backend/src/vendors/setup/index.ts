import * as dotenv from 'dotenv';
import { resolve } from 'path';
import { createCollections } from './createCollections';
import { createIndexes } from './createIndexes';
import { provisionGiamDeks, findOrphanedDeks } from '../encryption/keyVault';
import { getQEClient, closeQEClient, assertCryptSharedLib } from '../encryption/qeClient';
import { config, keyVaultNamespace } from '../../config';

// Works regardless of CWD: npm --prefix changes it to giam/backend/.
dotenv.config({ path: resolve(__dirname, '../../../../../.env') });

export async function runSetup(reset = false): Promise<void> {
  if (!config.mongodb.uri) {
    throw new Error(
      'GIAM_DB_URI / MONGODB_URI is not set.\n'
      + '  GIAM defaults to the platform cluster with its OWN database (GIAM_DB_NAME) and its own key vault.',
    );
  }

  // Validate before connecting: a wrong crypt_shared path fails the connection itself and reads as a
  // plain connectivity error.
  console.log(`crypt_shared: ${assertCryptSharedLib()}`);
  console.log(`key vault:    ${keyVaultNamespace()} (GIAM's own, inside its own database)\n`);

  const client = await getQEClient();
  try {
    const db = client.db(config.mongodb.dbName);
    console.log(`Connected to the GIAM database "${config.mongodb.dbName}"\n`);

    // A database whose vault was dropped points at DEKs that no longer exist. Fail here with the
    // remedy instead of at the first encrypted read with a driver-level message.
    if (!reset) {
      const orphans = await findOrphanedDeks(client);
      if (orphans.length > 0) {
        throw new Error(
          `These collections reference DEKs that no longer exist in ${keyVaultNamespace()}: ${orphans.join(', ')}.\n`
          + '  Rebuild with:  npm run setup:db:reset --prefix giam/backend',
        );
      }
    }

    console.log('1. Provisioning the key vault and GIAM\'s own DEKs...');
    const deks = await provisionGiamDeks(client, reset);
    console.log('');

    console.log('2. Creating collections...');
    await createCollections(db, deks, reset);
    console.log('');

    console.log('3. Creating indexes...');
    await createIndexes(db);
    console.log('');

    console.log('GIAM setup complete.');
    console.log('  Seed it with: npm run setup:seed --prefix giam/backend');
  } finally {
    await closeQEClient();
  }
}
