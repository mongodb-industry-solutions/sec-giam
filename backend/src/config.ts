import * as dotenv from 'dotenv';
import { resolve } from 'path';

dotenv.config({ path: resolve(__dirname, '../../../.env') });

// Every GIAM variable carries the GIAM_ prefix. GIAM is a product other deployments reuse, so it owns
// its own namespace and never reads another service's configuration.
function giamEnv(name: string, fallback?: string): string | undefined {
  return process.env[`GIAM_${name}`] ?? fallback;
}

// Standard globals and already-prefixed external-system variables, read as they are.
function env(name: string, fallback?: string): string | undefined {
  return process.env[name] ?? fallback;
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return !['false', 'off', 'no', '0'].includes(value.trim().toLowerCase());
}

// Custody of the private signing key. Not an environment gate: every mode runs on a laptop and on a
// cluster, and the default is multi-replica correct with no KMS, no shared volume and no shared secret.
export type KeyProviderName = 'instance-local' | 'kms' | 'shared-store' | 'filesystem';

// A stable per-process identity, so a replica can claim and renew a lease on its own signing key.
function resolveInstanceId(): string {
  return giamEnv('INSTANCE_ID')
    ?? env('HOSTNAME')
    ?? `local-${process.pid}`;
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',

  server: {
    host: env('HOST', '0.0.0.0')!,
    // Own port, chosen not to collide with the other services in this deployment.
    port: parseInt(giamEnv('PORT', '8085')!, 10),
    // Private, service to service. What a resource server resolves discovery against.
    baseUrl: giamEnv('BASE_URL', 'http://127.0.0.1:8085')!,
    // Public, browser facing. Empty when a deployment does not publish GIAM.
    publicUrl: giamEnv('PUBLIC_URL', '')!,
    // The GIAM frontend, where the login, consent and administration screens live.
    frontendUrl: giamEnv('FRONTEND_URL', 'http://localhost:8086')!,
    corsOrigin: giamEnv('CORS_ORIGIN', 'http://localhost:8086')!,
  },

  mongodb: {
    // A connection convenience, not a data one: one cluster sets MONGODB_URI and every service uses it,
    // while a deployment that separates GIAM sets GIAM_DB_URI and nothing else changes. The DATABASE is
    // always distinct, and GIAM never reads another service's collections.
    uri: giamEnv('DB_URI') ?? env('MONGODB_URI', '')!,
    dbName: giamEnv('DB_NAME', 'giamdb')!,
    // The key vault is a COLLECTION inside that same database: one connection, one lifecycle, and a
    // reset rebuilds vault and data together with no second cleanup path to forget.
    keyVaultCollection: giamEnv('DB_KEYVAULT', 'keyVault')!,
    cryptSharedLibPath: giamEnv('CRYPT_SHARED_LIB_PATH')
      ?? env('MONGODB_CRYPT_SHARED_LIB_PATH', '')!,
    // QE substring search needs crypt_shared 8.2+ and server 8.2+. Off, the searched field degrades to
    // equality: still encrypted, still exactly searchable, and setup still succeeds on an older cluster.
    textSearch: bool(giamEnv('QE_TEXT_SEARCH'), true),
  },

  kms: {
    // GIAM's own provider configuration and its own DEKs. Never the platform vault the applications
    // share: an identity system that shares key material with what it protects cannot contain a breach.
    provider: (giamEnv('KMS_PROVIDER', 'local')!) as 'local' | 'aws',
    localMasterKey: giamEnv('KMS_LOCAL_MASTER_KEY'),
    awsCmkArn: giamEnv('KMS_AWS_CMK_ARN') ?? env('AWS_CMK_ARN'),
    awsRegion: giamEnv('KMS_AWS_REGION') ?? env('AWS_REGION', 'us-east-1')!,
  },

  keys: {
    // Per-instance keys with one shared published key set. Correct on one replica and on twenty.
    provider: (giamEnv('KEY_PROVIDER', 'instance-local')!) as KeyProviderName,
    instanceId: resolveInstanceId(),
    // Where instance-local and filesystem hold their private material.
    storeDir: giamEnv('KEY_STORE_DIR', './keys')!,
    // A replica renews this while it lives; when it lapses the key stops signing but stays published.
    leaseSeconds: parseInt(giamEnv('KEY_LEASE_SECONDS', '300')!, 10),
    heartbeatSeconds: parseInt(giamEnv('KEY_HEARTBEAT_SECONDS', '60')!, 10),
    // Publication grace after a lease lapses, so tokens already signed still verify. Must be at least
    // the maximum access-token lifetime, or a scale-down invalidates live sessions.
    publicationGraceSeconds: parseInt(giamEnv('KEY_PUBLICATION_GRACE_SECONDS', '3600')!, 10),
    // kms provider
    awsKeyArn: giamEnv('KEY_AWS_KEY_ARN'),
    awsRegion: giamEnv('KEY_AWS_REGION') ?? env('AWS_REGION', 'us-east-1')!,
    // shared-store provider: the KEK that wraps the stored private key, held OUTSIDE the database.
    wrappingKey: giamEnv('KEY_WRAPPING_KEY'),
    // Declared replica count. Used to report posture, never to refuse to start.
    replicas: parseInt(giamEnv('REPLICAS', '1')!, 10),
  },

  app: {
    eventBusEngine: (giamEnv('EVENT_BUS_ENGINE', 'in-process')!) as 'in-process' | 'kafka' | 'rabbitmq',
    eventBusTopicPrefix: giamEnv('EVENT_BUS_TOPIC_PREFIX', 'giam')!,
    seedDataDir: giamEnv('SEED_DATA_DIR'),
    // Administrative surface credential, until GIAM issues its own administrative tokens (P6).
    adminToken: giamEnv('ADMIN_TOKEN'),
    // Swagger UI and the committed OpenAPI document.
    docsEnabled: bool(giamEnv('DOCS_ENABLED'), true),
  },

  kafka: {
    brokers: (giamEnv('KAFKA_BROKERS', 'localhost:9092')!).split(',').map((s) => s.trim()),
    clientId: giamEnv('KAFKA_CLIENT_ID', 'giam')!,
    ssl: bool(giamEnv('KAFKA_SSL'), false),
    saslMechanism: giamEnv('KAFKA_SASL_MECHANISM'),
    saslUsername: giamEnv('KAFKA_SASL_USERNAME'),
    saslPassword: giamEnv('KAFKA_SASL_PASSWORD'),
  },

  rabbitmq: {
    url: giamEnv('RABBITMQ_URL', 'amqp://localhost')!,
  },
} as const;

// Composed here rather than configured as a string, so the database and the vault cannot drift apart.
export function keyVaultNamespace(): string {
  return `${config.mongodb.dbName}.${config.mongodb.keyVaultCollection}`;
}

export function keyVaultNamespaceParts(): { database: string; collection: string } {
  return { database: config.mongodb.dbName, collection: config.mongodb.keyVaultCollection };
}

// The absolute issuer URL of a realm. Every token names it, and every verifier compares against it.
export function realmIssuer(realmName: string): string {
  const base = (config.server.publicUrl || config.server.baseUrl).replace(/\/+$/, '');
  return `${base}/realms/${realmName}`;
}
