import { existsSync } from 'fs';
import { keyProviders } from '../../../shared/ports';
import { config, ClientEnforcementMode } from '../../../config';

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
  /**
   * How each realm treats a client that has not registered.
   *
   * Per realm, because onboarding is something one realm goes through while the others beside it are
   * already established, and a single process-wide answer would hide exactly that.
   */
  clientRegistration: {
    /** What a realm inherits when its record states nothing. */
    defaultMode: ClientEnforcementMode;
    realms: Array<{ realm: string; mode: ClientEnforcementMode }>;
  };
  administration: {
    credentialConfigured: boolean;
    /**
     * Whether whoever holds the administrative credential can run an arbitrary command in the
     * checkout. Reported rather than gated: it is a reasonable thing for an operator to be able to do
     * and an unreasonable thing to have to infer.
     */
    shellReachable: boolean;
  };
  findings: PostureFinding[];
}

export interface PostureInput {
  databaseReachable: boolean;
  databaseError?: string | null;
  /** The realms and the enforcement in force for each. Empty when the database is unreachable. */
  realms?: Array<{ name: string; mode: ClientEnforcementMode }>;
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

  // One finding per soft realm, named, so the banner says WHICH realm is admitting strangers rather
  // than that something somewhere is.
  const realms = input.realms ?? [];
  for (const realm of realms.filter((entry) => entry.mode === 'soft')) {
    findings.push({
      code: 'client_enforcement_soft',
      level: 'degraded',
      detail:
        `Realm "${realm.name}" admits a client that is not registered. Such a client is admitted `
        + 'with reduced authority (no permissions claim, no roles claim, no refresh token, scope cut '
        + 'to openid) and every admission is recorded as a client.soft_admission security event, but '
        + 'an unregistered caller still obtains a token. This is an onboarding ramp, not a setting to '
        + 'leave in place.',
      remedy:
        'Register the clients listed by the client.soft_admission events, then set clientEnforcement '
        + 'on the realm record to "strict" (or unset it, and leave GIAM_CLIENT_ENFORCEMENT at strict).',
    });
  }

  const administrationConfigured = Boolean(config.app.adminToken)
    || Boolean(config.app.adminUser && config.app.adminPasswordSha256);
  if (!administrationConfigured) {
    findings.push({
      code: 'administration_closed',
      level: 'degraded',
      detail: 'No administrative credential is configured, so the operational surface refuses every call.',
      remedy: 'Set GIAM_ADMIN_TOKEN, or GIAM_ADMIN_USER with GIAM_ADMIN_PASSWORD_SHA256.',
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
    clientRegistration: {
      defaultMode: config.app.clientEnforcement,
      realms: realms.map((realm) => ({ realm: realm.name, mode: realm.mode })),
    },
    administration: {
      credentialConfigured: administrationConfigured,
      shellReachable: config.app.adminShell,
    },
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
    '   Full report: GET /api/v1/admin/posture',
  ];
}
