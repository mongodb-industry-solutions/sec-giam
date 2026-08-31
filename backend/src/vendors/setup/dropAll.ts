import * as dotenv from 'dotenv';
import { resolve } from 'path';
import { getQEClient, closeQEClient } from '../encryption/qeClient';
import { config, keyVaultNamespace } from '../../config';

dotenv.config({ path: resolve(__dirname, '../../../../../.env') });

/**
 * Drops the GIAM database, and with it GIAM's key vault and every DEK in it.
 *
 * That is deliberate and it is safe HERE and only here: setup plus seed are the only way this database
 * is built, so every record is reproducible. It would not be acceptable for a database holding data
 * that cannot be regenerated, and nothing else on the platform is touched: the applications' shared
 * vault is not GIAM's and is never reached from this path.
 */
export async function dropAll(): Promise<void> {
  if (!config.mongodb.uri) throw new Error('GIAM_DB_URI / MONGODB_URI is not set');
  const client = await getQEClient();
  try {
    await client.db(config.mongodb.dbName).dropDatabase();
    console.log(`  dropped database: ${config.mongodb.dbName}`);
    console.log(`  dropped key vault: ${keyVaultNamespace()} (it lives inside that database)`);
    console.log('  the applications\' own key vault is untouched: GIAM never shared it');
  } finally {
    await closeQEClient();
  }
}
