import * as dotenv from 'dotenv';
import { hostname } from 'os';
import { resolve } from 'path';
import { API_PREFIX } from './shared/models/routes';

// The repo root .env, or backend/.env. Several candidates because this file runs both from source
// (backend/src, backend/bin) and from the build output (backend/dist/...), which sit at different
// depths; the first file that exists wins and a missing one is not an error.
dotenv.config({ path: ['../.env', '../../.env', '../../../.env'].map((p) => resolve(__dirname, p)) });

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

/**
 * What happens when a caller presents a client that is not registered.
 *
 * `strict` refuses it, which is the only correct answer once a deployment is established. `soft`
 * admits it with reduced authority, records the admission and reports the realm as degraded, so an
 * onboarding deployment can be brought up before every consumer has been registered without the
 * refusals being invisible. It is an onboarding ramp with evidence, not a security setting.
 */
export type ClientEnforcementMode = 'strict' | 'soft';

function enforcementMode(value: string | undefined): ClientEnforcementMode {
  return value?.trim().toLowerCase() === 'soft' ? 'soft' : 'strict';
}

/**
 * A stable per-REPLICA identity, so a replica can claim and renew a lease on its own signing key.
 *
 * Stable is the whole requirement, and the process id is the one thing here that is not. Keying on it
 * made every restart a new replica that mints a new key and leaves the old one published forever, so a
 * laptop accumulated one phantom replica per `npm run dev` and no amount of stopping the process could
 * clear them, because they live in the database rather than in the process table.
 *
 * On a cluster the pod name is the right answer and arrives in the environment. Off one, the host and
 * the port are what actually distinguish one deployment from another on the same machine.
 */
function resolveInstanceId(port: string): string {
  return giamEnv('INSTANCE_ID')
    ?? env('HOSTNAME')
    ?? `local-${hostname().toLowerCase()}-${port}`;
}

const serverPort = giamEnv('PORT', '8085')!;

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',

  server: {
    host: env('HOST', '0.0.0.0')!,
    // Own port, chosen not to collide with the other services in this deployment.
    port: parseInt(serverPort, 10),
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
    /**
     * WHICH MongoDB this is, and which version. Read by `vendors/mongodb/deployment`, which turns
     * the pair into the capability set every version-sensitive decision is taken from.
     *
     * Shared with the rest of the platform in the same way the connection string is: one cluster
     * sets MONGODB_TYPE and MONGODB_VERSION once, and a deployment that gives GIAM its own cluster
     * overrides them with GIAM_DB_TYPE and GIAM_DB_VERSION. Declared rather than assumed, because
     * setup and the seeder must reason about capability BEFORE they connect; both are reconciled
     * against the live cluster once a connection exists, and the cluster wins.
     */
    type: giamEnv('DB_TYPE') ?? env('MONGODB_TYPE', 'atlas')!,
    version: giamEnv('DB_VERSION') ?? env('MONGODB_VERSION', '8.2.4')!,
    // The key vault is a COLLECTION inside that same database: one connection, one lifecycle, and a
    // reset rebuilds vault and data together with no second cleanup path to forget.
    keyVaultCollection: giamEnv('DB_KEYVAULT', 'keyVault')!,
    cryptSharedLibPath: giamEnv('CRYPT_SHARED_LIB_PATH')
      ?? env('MONGODB_CRYPT_SHARED_LIB_PATH', '')!,
    // v44 RETIRED GIAM_QE_TEXT_SEARCH. Substring search on encrypted names is not a preference: it
    // is available on server 9.0+ with automatic encryption and unavailable below, which the type
    // and version above already answer. A second switch could only ever disagree with them, and a
    // deployment that set it to true on an 8.x cluster failed setup rather than degrading.
    // `vendors/mongodb/deployment` derives it now.
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
    instanceId: resolveInstanceId(serverPort),
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
    /**
     * How long the audit trail is kept, in days.
     *
     * CONFIGURATION and not a constant, because the requirement names no number. NIST SP 800-53
     * AU-11 and ISO/IEC 27001 A.8.15 say evidence must be retained and leave the period to the
     * regime; PCI DSS 10.5.1 is one such regime and asks for twelve months, which is the default
     * here because it is what this deployment must meet. A retail or agent deployment sets its own
     * against the same implementation, which is the whole point of not baking one industry's
     * regime into an authority meant to serve several.
     *
     * Zero disables expiry, for a deployment that archives externally and wants nothing removed.
     */
    auditRetentionDays: Number(giamEnv('AUDIT_RETENTION_DAYS', '365')),
    // Administrative surface credential, until GIAM issues its own administrative tokens (P6).
    adminToken: giamEnv('ADMIN_TOKEN'),
    // The operator the console signs in as, and the SHA-256 of the password it must present. The
    // plaintext is never configured, so a leaked configuration file does not hand over the console.
    // Named to match the platform convention an operator already knows, with its own prefix.
    adminUser: giamEnv('ADM_USER'),
    adminPasswordSha256: giamEnv('ADM_PASS'),
    // Whether the console may run an arbitrary shell command. Configuration, not an environment check:
    // the same build behaves the same way everywhere and the posture report says which way it is.
    adminShell: bool(giamEnv('ADMIN_SHELL'), true),
    // The checkout root the console runs scripts from. Explicit beats guessing from __dirname, which
    // gains a level once the code is compiled.
    projectRoot: giamEnv('PROJECT_ROOT'),
    // Swagger UI and the committed OpenAPI document.
    docsEnabled: bool(giamEnv('DOCS_ENABLED'), true),
    // The default a realm inherits when its record does not state one. strict, deliberately.
    clientEnforcement: enforcementMode(giamEnv('CLIENT_ENFORCEMENT')),
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
  return `${base}${API_PREFIX}/realms/${realmName}`;
}
