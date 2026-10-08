import { existsSync } from 'fs';
import { join } from 'path';

/**
 * The single source of truth for what a MongoDB deployment is (Atlas, Enterprise Advanced or
 * Community Edition; which version) and what that implies: Queryable Encryption query-type
 * naming, the broader capability set (range queries, change streams, time series, Atlas Search,
 * audit log), crypt_shared library resolution, and which installation/setup commands apply
 * (Atlas Admin API steps only exist on Atlas).
 *
 * Vendored identically into every repo that needs it (PSP, bankcore, GIAM) as a `file:` dependency,
 * never published to a registry: the copies must be kept byte-for-byte in sync by hand.
 *
 * Pure on purpose (no config, no `mongodb` dependency): every app reads it to derive its own
 * defaults, and the setup, validation and runtime paths all check against the same table.
 * `detectDeployment` takes a structurally-typed `MongoClientLike` rather than importing the real
 * driver, so this package never has to track whichever `mongodb` version each vendored copy sits
 * next to.
 */

/** Deployment kind. Only Atlas exposes the Admin API that provisions custom roles and DB users. */
export type MongoDeploymentType = 'atlas' | 'ea' | 'ce';

export interface MongoVersion {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

/** Tolerant of a build suffix (9.0.0-rc0, 8.2.4+atlas): only the numeric head decides a capability. */
export function parseVersion(raw: string): MongoVersion {
  const match = /^(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(raw.trim());
  if (!match) return { major: 0, minor: 0, patch: 0, raw };
  return {
    major: Number(match[1]),
    minor: Number(match[2] ?? 0),
    patch: Number(match[3] ?? 0),
    raw: raw.trim(),
  };
}

/** True when `version` is at least major.minor. Patch never gates a feature. */
export function atLeast(version: MongoVersion, major: number, minor = 0): boolean {
  return version.major > major || (version.major === major && version.minor >= minor);
}

/** Numeric comparison of dotted versions; missing segments count as 0, suffixes like -rc0 ignored. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => v.split('-')[0].split('.').map((p) => parseInt(p, 10) || 0);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const diff = (x[i] ?? 0) - (y[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/** The one parser for MONGODB_TYPE (or a prefixed equivalent like GIAM_DB_TYPE). */
export function parseDeploymentType(raw: string | undefined): MongoDeploymentType {
  const value = raw?.trim().toLowerCase();
  if (value === 'ce' || value === 'community') return 'ce';
  if (value === 'ea' || value === 'enterprise') return 'ea';
  return 'atlas';
}

/**
 * The declared deployment before any connection exists. Atlas is always a replica set; a
 * self-managed or Community deployment may be a standalone, and assuming otherwise would promise
 * a change stream that cannot start.
 */
export function declaredDeployment(type: MongoDeploymentType, version: string): MongoDeployment {
  return {
    type,
    version: parseVersion(version),
    source: 'declared',
    replicaSet: type === 'atlas',
  };
}

export interface QeProfile {
  /** Human label for logs and setup output. */
  label: string;
  /** Whether this version supports QE text search at all. */
  textSearch: boolean;
  substring: string;
  prefix: string;
  suffix: string;
  /** Largest strMaxQueryLength the server accepts for substring without a parameter-limit override. */
  substringMaxQueryLength: number;
  /** crypt_shared series that matches this server, stated in warnings. */
  cryptShared: string;
}

/**
 * Version ranges, oldest first. `from` is inclusive, the next entry's `from` is the exclusive
 * upper bound. A version newer than every entry uses the last one (the newest known behaviour)
 * rather than failing, so a server upgrade does not take the demo down; setup warns instead.
 */
const PROFILES: { from: string; profile: QeProfile }[] = [
  {
    from: '0.0.0',
    profile: {
      label: 'pre-8.2 (no QE text search)',
      textSearch: false,
      substring: 'equality', prefix: 'equality', suffix: 'equality',
      substringMaxQueryLength: 0,
      cryptShared: 'any',
    },
  },
  {
    from: '8.2.0',
    profile: {
      label: '8.2-8.3 (preview query types)',
      textSearch: true,
      substring: 'substringPreview', prefix: 'prefixPreview', suffix: 'suffixPreview',
      substringMaxQueryLength: 10,
      cryptShared: '8.2.x-8.3.x',
    },
  },
  {
    from: '9.0.0',
    profile: {
      label: '9.0+ (GA query types)',
      textSearch: true,
      substring: 'substring', prefix: 'prefix', suffix: 'suffix',
      // Server 9.0 rejects anything above 6 here (error 12860002).
      substringMaxQueryLength: 6,
      cryptShared: '9.0.x',
    },
  },
];

/** The recommended crypt_shared series for the reference deployment (Atlas, current default). */
export const MONGODB_CRYPT_SHARED_LIB_VERSION = '9.0.2';

/** The reference server version this package defaults to when nothing declares one. */
export const DEFAULT_MONGODB_VERSION = '9.0.0';

/** The profile for a declared server version. */
export function resolveQeProfile(version: string): QeProfile {
  let match = PROFILES[0].profile;
  for (const entry of PROFILES) {
    if (compareVersions(version, entry.from) >= 0) match = entry.profile;
  }
  return match;
}

/** True when the Atlas Admin API is available to provision custom roles and DB users. */
export function supportsAtlasAdminApi(type: MongoDeploymentType): boolean {
  return type === 'atlas';
}

/**
 * Compares the declared version with the one the cluster reports. A mismatch across a profile
 * boundary picks the wrong query type names for the whole database, and surfaces later as an
 * unrelated 500, so it is reported at setup time.
 */
export function versionMismatch(declared: string, actual: string): string | null {
  const a = resolveQeProfile(declared);
  const b = resolveQeProfile(actual);
  if (a === b) return null;
  return `MONGODB_VERSION declares ${declared} (${a.label}) but the cluster reports ${actual} `
    + `(${b.label}). Set MONGODB_VERSION=${actual} and use a crypt_shared ${b.cryptShared} library.`;
}

/** One-line description of the declared target, for setup and startup logs. */
export function describeTarget(type: MongoDeploymentType, version: string): string {
  const profile = resolveQeProfile(version);
  const label = type === 'atlas' ? 'Atlas' : type === 'ea' ? 'Enterprise Advanced' : 'Community Edition';
  return `${label} ${version}, QE ${profile.label}`;
}

export interface EncryptedFieldQuery {
  /** `collection.path` of the encrypted field. */
  path: string;
  /** Declared query type, or 'none' for a field that is encrypted but not searchable. */
  queryType: string;
}

/**
 * Compares the encrypted fields a deployment declares with the ones actually stored in the
 * database. A collection created under a different query type keeps refusing every encrypted
 * query on it, not only the text ones, and nothing short of recreating it repairs that, so the
 * difference is named field by field.
 */
export function encryptedFieldsDrift(
  expected: EncryptedFieldQuery[],
  stored: EncryptedFieldQuery[],
): string | null {
  const storedByPath = new Map(stored.map((f) => [f.path, f.queryType]));
  const differences: string[] = [];
  for (const field of expected) {
    const actual = storedByPath.get(field.path);
    if (actual === undefined) continue;               // collection not created yet: reported elsewhere
    if (actual !== field.queryType) differences.push(`${field.path}: stored ${actual}, expected ${field.queryType}`);
  }
  if (differences.length === 0) return null;
  return `${differences.length} encrypted field(s) differ from the declared configuration `
    + `(${differences.join('; ')}). Recreate them: setup:db:drop then setup:db.`;
}

/**
 * Best-effort check of the crypt_shared library actually configured. The path is the only version
 * information available before the driver fails, and pointing at the wrong series is the most
 * common way to break this, so a naming hint is worth a warning (never an error).
 */
export function cryptSharedHint(version: string, libPath: string): string | null {
  const found = /(\d+)\.(\d+)\.\d+/.exec(libPath);
  if (!found) return null;
  const libSeries = `${found[1]}.${found[2]}`;
  const profile = resolveQeProfile(version);
  const wanted = profile.cryptShared;
  if (wanted === 'any' || wanted.includes(libSeries)) return null;
  return `MONGODB_CRYPT_SHARED_LIB_PATH looks like crypt_shared ${libSeries}, but a server ${version} `
    + `deployment needs ${wanted}. Text-search fields will be refused if this is wrong.`;
}

// ── Full deployment + capability model ──────────────────────────────────────────────────────

export interface MongoDeployment {
  type: MongoDeploymentType;
  version: MongoVersion;
  /** Where the answer came from. 'declared' until a connection has been probed. */
  source: 'declared' | 'detected';
  /** A replica set or a sharded cluster, which is what change streams and transactions need. */
  replicaSet: boolean;
  /** Set when the probe disagreed with the declaration, in operator words. */
  mismatch?: string;
}

/**
 * What a deployment supports. Derived, never configured: an operator declares the deployment, not
 * the consequences of it, so no two flags can contradict each other.
 */
export interface MongoCapabilities {
  /** Server-side Queryable Encryption: createCollection with encryptedFields. All editions, 7.0+. */
  queryableEncryption: boolean;
  /**
   * AUTOMATIC encryption, the crypt_shared query analysis every consumer of this package relies
   * on. Enterprise and Atlas only. Community can hold QE collections but cannot rewrite a query
   * against them, so every encrypted read fails with a driver-level message about query analysis
   * rather than a clear one.
   */
  automaticEncryption: boolean;
  /** The `range` query type on an encrypted field. GA in 8.0. */
  qeRange: boolean;
  /** The resolved QE text-search query-type naming for this version (see `resolveQeProfile`). */
  qeTextSearchProfile: QeProfile;
  /** Needs a replica set or a sharded cluster. Live-session caches and similar degrade without it. */
  changeStreams: boolean;
  transactions: boolean;
  /** Time series collections, and expireAfterSeconds on one. Both 5.0. */
  timeSeries: boolean;
  timeSeriesExpiry: boolean;
  /** $search and $vectorSearch. Atlas only. */
  atlasSearch: boolean;
  /** Server-side audit logging, which PCI DSS 10 evidence can be corroborated against. */
  serverAuditLog: boolean;
  /** Whether the Atlas Admin API is available to provision custom roles and DB users. */
  supportsAtlasAdminApi: boolean;
}

export function capabilitiesOf(deployment: MongoDeployment): MongoCapabilities {
  const { type, version, replicaSet } = deployment;
  const queryableEncryption = atLeast(version, 7, 0);
  const automaticEncryption = queryableEncryption && type !== 'ce';
  return {
    queryableEncryption,
    automaticEncryption,
    qeRange: automaticEncryption && atLeast(version, 8, 0),
    // Both halves are required: the query type has to exist on the server AND the driver has to be
    // able to analyse a query against it, or declaring it buys an index nothing can use.
    qeTextSearchProfile: automaticEncryption ? resolveQeProfile(version.raw) : resolveQeProfile('0.0.0'),
    changeStreams: replicaSet,
    transactions: replicaSet,
    timeSeries: atLeast(version, 5, 0),
    timeSeriesExpiry: atLeast(version, 5, 0),
    atlasSearch: type === 'atlas',
    serverAuditLog: type !== 'ce',
    supportsAtlasAdminApi: type === 'atlas',
  };
}

interface BuildInfo {
  version?: string;
  modules?: string[];
  // Present on Atlas, absent everywhere else. The most direct signal there is.
  atlasVersion?: string;
}

interface HelloInfo {
  setName?: string;
  msg?: string;
  hosts?: string[];
}

/**
 * The slice of `MongoClient` this package actually needs, declared structurally rather than
 * imported from `mongodb`. Kept dependency-free on purpose: a real `MongoClient` already satisfies
 * this shape, and importing the driver's own class would tie every vendored copy of this package
 * to the exact `mongodb` version installed alongside it, which is the opposite of what a
 * compatibility module should require.
 */
export interface MongoClientLike {
  db(name: string): {
    command(cmd: Record<string, unknown>): Promise<Record<string, unknown>>;
  };
  options?: {
    srvHost?: string;
    hosts?: Array<{ toString(): string }>;
  };
}

export function classifyProbe(build: BuildInfo, hello: HelloInfo, uri: string): MongoDeployment {
  const version = parseVersion(build.version ?? DEFAULT_MONGODB_VERSION);
  const isAtlas = Boolean(build.atlasVersion) || /\.mongodb\.net\b/i.test(uri);
  const isEnterprise = (build.modules ?? []).includes('enterprise');
  const type: MongoDeploymentType = isAtlas ? 'atlas' : isEnterprise ? 'ea' : 'ce';
  return {
    type,
    version,
    source: 'detected',
    // `msg: isdbgrid` is a mongos, which is a sharded cluster and supports both.
    replicaSet: Boolean(hello.setName) || hello.msg === 'isdbgrid',
  };
}

function describeMismatch(declared: MongoDeployment, actual: MongoDeployment): string | undefined {
  const notes: string[] = [];
  if (declared.type !== actual.type) {
    notes.push(`MONGODB_TYPE declares "${declared.type}" but the cluster is "${actual.type}"`);
  }
  if (declared.version.major !== actual.version.major || declared.version.minor !== actual.version.minor) {
    notes.push(`MONGODB_VERSION declares "${declared.version.raw}" but the cluster reports "${actual.version.raw}"`);
  }
  if (notes.length === 0) return undefined;
  // Stated as informational rather than fatal: the probe is authoritative and the run continues
  // against what is really there. The declaration is still worth fixing, because it is what setup
  // reasons from before it ever connects.
  return `${notes.join('; ')}. The detected values are in force; correct the environment to match.`;
}

/**
 * Probes the live deployment and returns the resolved answer.
 *
 * Never throws. A cluster that refuses `buildInfo` to this user is a permission posture, not a
 * reason to stop: the declared deployment is returned instead and the failure is reported.
 */
export async function detectDeployment(client: MongoClientLike, declared: MongoDeployment): Promise<MongoDeployment> {
  try {
    const admin = client.db('admin');
    const build = await admin.command({ buildInfo: 1 }) as BuildInfo;
    const hello = await admin.command({ hello: 1 }) as HelloInfo;
    const uriHint = client.options?.srvHost ?? (client.options?.hosts ?? []).map((h) => h.toString()).join(',');
    const actual = classifyProbe(build, hello, uriHint);
    return { ...actual, mismatch: describeMismatch(declared, actual) };
  } catch (err) {
    return {
      ...declared,
      mismatch: `the deployment could not be probed (${err instanceof Error ? err.message : String(err)}); `
        + 'the declared MONGODB_TYPE and MONGODB_VERSION are in force',
    };
  }
}

export function describeDeployment(current: MongoDeployment): string {
  const topology = current.replicaSet ? 'replica set' : 'standalone';
  return `${current.type} ${current.version.raw} (${topology}, ${current.source})`;
}

/**
 * The capability lines for startup and setup reports, warning on anything a QE-dependent app
 * needs and this deployment cannot give it.
 */
export function capabilityFindings(current: MongoDeployment): Array<{ text: string; warn: boolean }> {
  const caps = capabilitiesOf(current);
  const findings: Array<{ text: string; warn: boolean }> = [];

  if (!caps.automaticEncryption) {
    findings.push({
      warn: true,
      text: current.type === 'ce'
        ? 'Community Edition cannot perform automatic encryption: every read of an encrypted '
          + 'field will fail. Atlas or Enterprise Advanced is required.'
        : `server ${current.version.raw} predates Queryable Encryption (7.0+); encrypted collections cannot be created`,
    });
  }
  if (caps.automaticEncryption && !caps.qeTextSearchProfile.textSearch) {
    findings.push({
      warn: false,
      text: `substring/prefix/suffix search on encrypted fields needs server 8.2+ (this is `
        + `${current.version.raw}); text fields fall back to equality, still encrypted and still exactly searchable`,
    });
  }
  if (!caps.changeStreams) {
    findings.push({
      warn: false,
      text: 'no replica set: change-stream-dependent features (live caches, revocation) fall back '
        + 'to polling or an authoritative read',
    });
  }
  if (!caps.timeSeriesExpiry) {
    findings.push({
      warn: true,
      text: `server ${current.version.raw} has no time series expiry; retention-sensitive time series cannot auto-expire`,
    });
  }
  if (current.mismatch) findings.push({ warn: true, text: current.mismatch });
  return findings;
}

// ── crypt_shared library resolution ─────────────────────────────────────────────────────────

const LIB_NAME: Partial<Record<NodeJS.Platform, string>> = {
  win32: 'mongo_crypt_v1.dll',
  darwin: 'mongo_crypt_v1.dylib',
  linux: 'mongo_crypt_v1.so',
};

const DEFAULT_PATHS: Partial<Record<NodeJS.Platform, string[]>> = {
  win32: [
    'C:/Program Files/MongoDB/Shared Library/bin/mongo_crypt_v1.dll',
    'C:/Program Files/MongoDB/Cryptography Library/bin/mongo_crypt_v1.dll',
    'C:/Program Files/MongoDB/Server/8.0/bin/mongo_crypt_v1.dll',
    'C:/Program Files/MongoDB/Server/7.0/bin/mongo_crypt_v1.dll',
  ],
  darwin: [
    '/usr/local/lib/mongo_crypt_v1.dylib',
    '/opt/homebrew/lib/mongo_crypt_v1.dylib',
    '/usr/lib/mongo_crypt_v1.dylib',
  ],
  linux: [
    '/usr/lib/mongo_crypt_v1.so',
    '/usr/local/lib/mongo_crypt_v1.so',
    '/usr/lib/x86_64-linux-gnu/mongo_crypt_v1.so',
  ],
};

export interface CryptLibResolution {
  /** Absolute path to the crypt_shared library, or undefined if not found. */
  path?: string;
  /** Where the path came from, so a caller can log or warn differently per source. */
  source: 'explicit' | 'default-path' | 'node_modules' | 'not-found';
}

/**
 * Resolves the MongoDB Automatic Encryption Shared Library path (mongo_crypt_v1.dll/.dylib/.so).
 *
 * Resolution order: 1) the explicit path, if it exists; 2) platform-specific default install
 * locations; 3) the `mongodb-client-encryption` package's own bundled binding, if present.
 * Download from https://www.mongodb.com/try/download/enterprise → select platform →
 * "Cryptography Library (crypt_shared)".
 */
export function resolveCryptSharedLibPath(explicitPath?: string): CryptLibResolution {
  if (explicitPath && existsSync(explicitPath)) return { path: explicitPath, source: 'explicit' };

  const libName = LIB_NAME[process.platform];
  if (libName) {
    for (const candidate of DEFAULT_PATHS[process.platform] ?? []) {
      if (existsSync(candidate)) return { path: candidate, source: 'default-path' };
    }
    try {
      const pkgJson = require.resolve('mongodb-client-encryption/package.json');
      const libPath = join(pkgJson, '..', 'lib', 'binding', libName);
      if (existsSync(libPath)) return { path: libPath, source: 'node_modules' };
    } catch { /* package not found - skip */ }
  }

  return { source: 'not-found' };
}

/**
 * Whether a driver error names an unsupported QE query type. Not a per-field failure: it means
 * the server or crypt_shared in use does not know the declared spelling (`substringPreview` on a
 * 9.0+ server, or the GA names on an older crypt_shared), which poisons the whole collection, not
 * only the text-search fields. Setup catches this and rebuilds the map with equality instead of
 * leaving the collection uncreated.
 */
export function isUnsupportedQueryTypeError(message: string): boolean {
  return /queryType|substring|prefix|suffix/i.test(message);
}
