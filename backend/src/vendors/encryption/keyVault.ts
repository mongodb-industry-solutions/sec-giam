import { MongoClient, Binary, ClientEncryption } from 'mongodb';
import { buildKmsProviders } from './qeClient';
import { GiamDeks, DEK_ALT_NAMES } from './encryptedFieldsMaps';
import { config, keyVaultNamespace, keyVaultNamespaceParts } from '../../config';

/**
 * Provisions GIAM's key vault and its own DEKs.
 *
 * The vault is a COLLECTION inside GIAM's database, so one connection and one reset rebuild vault and
 * data together. Two consequences worth stating rather than discovering: dropping the database
 * destroys the DEKs and everything encrypted under them, which is acceptable only because setup and
 * seed are the only way this database is built and every record is reproducible; and a dump contains
 * ciphertext and wrapped DEKs together, which discloses nothing on its own because the DEKs are
 * themselves encrypted under the master key the KMS provider holds.
 */
/**
 * Provisions the vault and this authority's data encryption keys.
 *
 * A reset DROPS the vault first, and it has to. A data key is wrapped by the master key, so a vault
 * that
 * survives a reset holds keys the CURRENT master key cannot unwrap, and the failure surfaces much
 * later as an HMAC validation error on the first encrypted write, which names neither the vault nor
 * the key. Keeping the vault across a reset was the one way to make a rebuild produce a database
 * that could not be read.
 */
export async function provisionGiamDeks(client: MongoClient, reset = false): Promise<GiamDeks> {
  const { database, collection } = keyVaultNamespaceParts();
  const clientEncryption = new ClientEncryption(client, {
    keyVaultNamespace: keyVaultNamespace(),
    kmsProviders: buildKmsProviders(),
  });
  const keyVault = client.db(database).collection(collection);

  if (reset) {
    // Dropped rather than emptied: the unique index is recreated below, and a half-cleared vault is
    // the state that produces the confusing failure this exists to prevent.
    await keyVault.drop().catch(() => { /* absent is the state we want */ });
    console.log('    dropped the vault, so every key is rewrapped under the current master key');
  }

  // The vault's own contract: one key per alt name, enforced by the database rather than by care.
  await keyVault.createIndex(
    { keyAltNames: 1 },
    { unique: true, partialFilterExpression: { keyAltNames: { $exists: true } }, name: 'keyAltNames_unique' },
  );

  const masterKey = config.kms.provider === 'aws' && config.kms.awsCmkArn
    ? { key: config.kms.awsCmkArn, region: config.kms.awsRegion }
    : undefined;

  async function getOrCreate(keyName: string): Promise<Binary> {
    const existing = await keyVault.findOne({ keyAltNames: keyName });
    if (existing) {
      console.log(`    reuse: ${keyName}`);
      return existing._id as unknown as Binary;
    }
    try {
      const id = await clientEncryption.createDataKey(config.kms.provider, { masterKey, keyAltNames: [keyName] });
      console.log(`    new:   ${keyName}`);
      return id as unknown as Binary;
    } catch (err) {
      // Losing the race between the read and this write is a clean refusal on the unique index, so
      // adopt the key the winner created rather than failing a concurrent setup.
      if ((err as { code?: number }).code !== 11000) throw err;
      const winner = await keyVault.findOne({ keyAltNames: keyName });
      if (!winner) throw err;
      console.log(`    reuse: ${keyName} (created concurrently)`);
      return winner._id as unknown as Binary;
    }
  }

  return {
    identityEmail: await getOrCreate(DEK_ALT_NAMES.identityEmail),
    identityPhone: await getOrCreate(DEK_ALT_NAMES.identityPhone),
    identityName: await getOrCreate(DEK_ALT_NAMES.identityName),
    apiKeyHash: await getOrCreate(DEK_ALT_NAMES.apiKeyHash),
  };
}

/**
 * Every keyId an encrypted collection was created with must still resolve in the vault.
 *
 * Left undetected, a stale reference surfaces on the first encrypted read as "not all keys requested
 * were satisfied", which reads like a driver fault rather than a database that outlived its keys.
 */
export async function findOrphanedDeks(client: MongoClient): Promise<string[]> {
  const { database, collection } = keyVaultNamespaceParts();
  const keyVault = client.db(database).collection(collection);
  const collections = await client.db(config.mongodb.dbName)
    .listCollections({}, { nameOnly: false })
    .toArray() as Array<{ name: string; options?: { encryptedFields?: { fields?: Array<{ keyId?: Binary }> } } }>;

  const orphans: string[] = [];
  for (const info of collections) {
    for (const field of info.options?.encryptedFields?.fields ?? []) {
      if (!field.keyId) continue;
      const found = await keyVault.countDocuments({ _id: field.keyId as never }, { limit: 1 });
      if (!found) orphans.push(info.name);
    }
  }
  return [...new Set(orphans)];
}
