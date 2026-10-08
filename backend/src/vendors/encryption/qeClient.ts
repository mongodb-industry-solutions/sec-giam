// Queryable Encryption client for GIAM. It points at GIAM's OWN key vault, a collection inside
// GIAM's own database, with GIAM's own DEKs. It never touches the vault the applications share: an
// identity system holding the same key material as what it protects has no compromise-containment
// story to tell.
//
// Resolved through the same chain as the PSP and bankcore (explicit path, then platform defaults,
// then node_modules) via @leafypay/mongo-compat, but still validated and HARD-FAILED at startup: a
// wrong or missing library fails the whole connection and surfaces as a generic 503, which is
// expensive to diagnose.
import { MongoClient, KMSProviders } from 'mongodb';
import { resolveCryptSharedLibPath } from '@leafypay/mongo-compat';
import { config, keyVaultNamespace } from '../../config';

let client: MongoClient | null = null;

export function buildKmsProviders(): KMSProviders {
  if (config.kms.provider === 'local') {
    const key = config.kms.localMasterKey;
    if (!key) throw new Error('GIAM_KMS_LOCAL_MASTER_KEY is required when GIAM_KMS_PROVIDER=local');
    return { local: { key: Buffer.from(key, 'base64') } };
  }
  const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
  const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
  const sessionToken = process.env.AWS_SESSION_TOKEN;
  if (!accessKeyId || !secretAccessKey) {
    throw new Error('AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required when GIAM_KMS_PROVIDER=aws');
  }
  return { aws: { accessKeyId, secretAccessKey, ...(sessionToken && { sessionToken }) } };
}

// Fails at startup rather than at the first encrypted read, where it looks like a connection outage.
export function assertCryptSharedLib(): string {
  const resolved = resolveCryptSharedLibPath(config.mongodb.cryptSharedLibPath);
  if (!resolved.path) {
    throw new Error(
      'crypt_shared library not found. Set GIAM_CRYPT_SHARED_LIB_PATH, or '
      + 'MONGODB_CRYPT_SHARED_LIB_PATH to share the platform value, or install it at a platform '
      + 'default location.',
    );
  }
  return resolved.path;
}

export async function getQEClient(): Promise<MongoClient> {
  if (client) return client;
  if (!config.mongodb.uri) throw new Error('GIAM_DB_URI or MONGODB_URI must be set');

  const cryptSharedLibPath = assertCryptSharedLib();

  client = new MongoClient(config.mongodb.uri, {
    autoEncryption: {
      keyVaultNamespace: keyVaultNamespace(),
      kmsProviders: buildKmsProviders(),
      extraOptions: {
        // Driver 7 types this as a `${string}mongo_crypt_v${number}.{so,dll,dylib}` template.
        cryptSharedLibPath: cryptSharedLibPath as `${string}mongo_crypt_v${number}.so`,
        cryptSharedLibRequired: true,
      },
    },
  });
  await client.connect();
  return client;
}

export async function closeQEClient(): Promise<void> {
  if (!client) return;
  const closing = client;
  client = null;
  await closing.close();
}
