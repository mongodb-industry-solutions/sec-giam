import { existsSync } from 'fs';
import { keyProviders } from '../../../shared/ports';
import { config } from '../../../config';

/**
 * The honest alternative to gating on environment.
 *
 * GIAM does not decide what an operator is allowed to run. What it does instead is make what IS
 * running impossible to misread: the posture endpoint reports the security properties actually in
 * force, as data. An operator running a weaker configuration is told so, in four places, and the
 * service still starts.
 *
 * A warning nobody sees is the same as no warning, which is why a degraded finding surfaces in the
 * startup log, on this endpoint, as a console banner and in the runbook's documented limitations.
 */

export type PostureLevel = 'ok' | 'degraded';

export interface PostureFinding {
  /** Machine readable, so an operator can alert on it rather than reading prose. */
  code: string;
  level: PostureLevel;
  /** The exact risk, not a category. */
  detail: string;
  /** What to change. A finding with no remedy is a complaint. */
  remedy: string;
}

export interface PostureReport {
  status: PostureLevel;
  instanceId: string;
  keyCustody: {
    provider: string;
    /** True when the private key is held outside this process, in a KMS or under a wrapping key. */
    externalCustody: boolean;
    /** True when every replica can verify what any replica signed. */
    multiReplicaCapable: boolean;
    /** How many replicas this deployment declares it runs. */
    declaredReplicas: number;
    publicationGraceSeconds: number;
    leaseSeconds: number;
  };
  tokenValidation: {
    /** Which models resource servers may choose between. Both are always available. */
    supportedModes: string[];
    /** Formats an access token may take. */
    formats: string[];
  };
  proofOfPossession: {
    /** Bearer is the floor. Anything beyond it that is actually wired appears here. */
    supported: string[];
  };
  attestation: {
    /** Whether a workload must prove what it is before it can obtain a token. */
    required: boolean;
  };
  storage: {
    database: string;
    reachable: boolean;
    /** GIAM's own vault, never the one the applications share. */
    keyVault: string;
    encryptionLibraryPresent: boolean;
    queryableTextSearch: boolean;
  };
  administration: {
    credentialConfigured: boolean;
  };
  findings: PostureFinding[];
}

export interface PostureInput {
  databaseReachable: boolean;
  databaseError?: string | null;
}

export function buildPostureReport(input: PostureInput): PostureReport {
  const findings: PostureFinding[] = [];

  const provider = keyProviders.has(config.keys.provider)
    ? keyProviders.resolve(config.keys.provider)
    : null;

  if (!provider) {
    findings.push({
      code: 'key_provider_unknown',
      level: 'degraded',
      detail: `GIAM_KEY_PROVIDER is "${config.keys.provider}", which no registered provider answers to.`,
      remedy: `Set it to one of: ${keyProviders.names().join(', ')}.`,
    });
  }

  // The one genuinely weaker configuration on this platform. With the default there is nothing to
  // warn about, which is the point of making it the default.
  if (config.keys.provider === 'filesystem' && config.keys.replicas > 1) {
    findings.push({
      code: 'key_path_may_not_be_shared',
      level: 'degraded',
      detail:
        `${config.keys.replicas} replicas are declared with the filesystem key provider. If `
        + `"${config.keys.storeDir}" is not a genuinely shared path, each replica signs with a `
        + 'different key that the others do not publish, and verification fails intermittently '
        + 'depending on which replica served the request.',
      remedy:
        'Use GIAM_KEY_PROVIDER=instance-local, which is multi-replica correct with no shared path '
        + 'at all, or confirm that GIAM_KEY_STORE_DIR is shared across every replica.',
    });
  }

  // A publication grace shorter than a token lifetime signs live sessions out on a scale-down.
  if (config.keys.publicationGraceSeconds < config.keys.leaseSeconds) {
    findings.push({
      code: 'publication_grace_too_short',
      level: 'degraded',
      detail:
        `The publication grace (${config.keys.publicationGraceSeconds}s) is shorter than the key `
        + `lease (${config.keys.leaseSeconds}s), so a key can leave the published set while tokens `
        + 'it signed are still valid.',
      remedy: 'Set GIAM_KEY_PUBLICATION_GRACE_SECONDS to at least the maximum access-token lifetime.',
    });
  }

  if (!config.app.adminToken) {
    findings.push({
      code: 'administration_closed',
      level: 'degraded',
      detail: 'No administrative credential is configured, so the operational surface refuses every call.',
      remedy: 'Set GIAM_ADMIN_TOKEN.',
    });
  }

  const encryptionLibraryPresent = Boolean(config.mongodb.cryptSharedLibPath)
    && existsSync(config.mongodb.cryptSharedLibPath);
  if (!encryptionLibraryPresent) {
    findings.push({
      code: 'encryption_library_missing',
      level: 'degraded',
      detail:
        'The encryption shared library is missing, so the database connection itself fails and every '
        + 'route reports an outage rather than an encryption problem.',
      remedy: 'Set GIAM_CRYPT_SHARED_LIB_PATH to an existing library of a version the cluster supports.',
    });
  }

  if (!input.databaseReachable) {
    findings.push({
      code: 'storage_unreachable',
      level: 'degraded',
      detail: input.databaseError ?? 'The database is not reachable.',
      remedy: 'Check GIAM_DB_URI and the cluster. Protected routes answer 503 until it returns.',
    });
  }

  return {
    status: findings.some((finding) => finding.level === 'degraded') ? 'degraded' : 'ok',
    instanceId: config.keys.instanceId,
    keyCustody: {
      provider: config.keys.provider,
      externalCustody: provider?.externalCustody ?? false,
      multiReplicaCapable: provider?.multiReplicaCapable ?? false,
      declaredReplicas: config.keys.replicas,
      publicationGraceSeconds: config.keys.publicationGraceSeconds,
      leaseSeconds: config.keys.leaseSeconds,
    },
    tokenValidation: {
      // Both, always. Which one applies is the resource server's choice per operation, not a build.
      supportedModes: ['local-jwks', 'introspection'],
      formats: ['jwt'],
    },
    proofOfPossession: { supported: ['bearer'] },
    attestation: { required: false },
    storage: {
      database: config.mongodb.dbName,
      reachable: input.databaseReachable,
      keyVault: `${config.mongodb.dbName}.${config.mongodb.keyVaultCollection}`,
      encryptionLibraryPresent,
      queryableTextSearch: config.mongodb.textSearch,
    },
    administration: { credentialConfigured: Boolean(config.app.adminToken) },
    findings,
  };
}

/** The console banner. One line per finding, so a degraded deployment is visible without a query. */
export function postureBanner(report: PostureReport): string[] {
  if (report.status === 'ok') return [];
  return [
    '!! GIAM is running in a DEGRADED posture',
    ...report.findings
      .filter((finding) => finding.level === 'degraded')
      .flatMap((finding) => [`   [${finding.code}] ${finding.detail}`, `   remedy: ${finding.remedy}`]),
    '   Full report: GET /admin/posture',
  ];
}
