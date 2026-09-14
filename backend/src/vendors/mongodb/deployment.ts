// What KIND of MongoDB GIAM is talking to, and what that deployment can actually do.
//
// Every feature this system depends on that is not universal (Queryable Encryption, the substring
// query type, change streams, time series expiry, Atlas Search) is gated HERE, in one place, rather
// than behind a hand-managed boolean per feature. A boolean per feature is what this codebase had:
// GIAM_QE_TEXT_SEARCH told setup to declare a substring index, and nothing checked whether the
// cluster behind the connection string could honour it, so a wrong answer failed at create time or,
// worse, at the first encrypted read.
//
// Two inputs, both from the environment, both with defaults that describe the reference deployment:
//   MONGODB_TYPE     atlas | ea | ce      (GIAM_DB_TYPE takes precedence)
//   MONGODB_VERSION  8.2.4, 9.0.0, ...    (GIAM_DB_VERSION takes precedence)
//
// The declared pair is what setup, the seeder and the encrypted-fields builder reason from, because
// they need an answer BEFORE and INDEPENDENTLY of a live connection. Once a connection exists, the
// deployment is PROBED and the declaration is reconciled against it: the probe wins, and a mismatch
// is reported rather than silently accepted, because a declaration that does not match the cluster
// is the exact condition this module exists to catch.

import type { MongoClient } from 'mongodb';
import { config } from '../../config';

/** atlas: MongoDB Atlas. ea: Enterprise Advanced, self-managed. ce: Community Edition. */
export type MongoDeploymentType = 'atlas' | 'ea' | 'ce';

export interface MongoVersion {
  major: number;
  minor: number;
  patch: number;
  raw: string;
}

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
 * What this deployment supports. Derived, never configured: an operator declares the deployment,
 * not the consequences of it, so no two flags can contradict each other.
 */
export interface MongoCapabilities {
  /** Server-side Queryable Encryption: createCollection with encryptedFields. All editions, 7.0+. */
  queryableEncryption: boolean;
  /**
   * AUTOMATIC encryption, the crypt_shared query analysis this codebase relies on. Enterprise and
   * Atlas only. Community can hold QE collections but cannot rewrite a query against them, so every
   * encrypted read fails with a driver-level message about query analysis rather than a clear one.
   */
  automaticEncryption: boolean;
  /** The `substring` query type on an encrypted field. GA in 9.0, under another name before it. */
  qeSubstring: boolean;
  /** The `range` query type on an encrypted field. GA in 8.0. */
  qeRange: boolean;
  /** Needs a replica set or a sharded cluster. The live-session cache degrades without it. */
  changeStreams: boolean;
  transactions: boolean;
  /** Time series collections, and expireAfterSeconds on one. Both 5.0. */
  timeSeries: boolean;
  timeSeriesExpiry: boolean;
  /** $search and $vectorSearch. Atlas only. */
  atlasSearch: boolean;
  /** Server-side audit logging, which PCI DSS 10 evidence can be corroborated against. */
  serverAuditLog: boolean;
}

const DEFAULT_TYPE: MongoDeploymentType = 'atlas';
const DEFAULT_VERSION = '8.2.4';

export function parseVersion(raw: string): MongoVersion {
  // Tolerant of a build suffix (9.0.0-rc0, 8.2.4+atlas): only the numeric head decides a capability.
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

export function parseDeploymentType(raw: string | undefined): MongoDeploymentType {
  const value = raw?.trim().toLowerCase();
  if (value === 'ce' || value === 'community') return 'ce';
  if (value === 'ea' || value === 'enterprise') return 'ea';
  // Anything unrecognised reads as the reference deployment rather than refusing to start: a typo in
  // one variable should not take an identity provider down.
  return value === 'atlas' || value === undefined || value === '' ? 'atlas' : DEFAULT_TYPE;
}

export function capabilitiesOf(deployment: MongoDeployment): MongoCapabilities {
  const { type, version, replicaSet } = deployment;
  const queryableEncryption = atLeast(version, 7, 0);
  const automaticEncryption = queryableEncryption && type !== 'ce';
  return {
    queryableEncryption,
    automaticEncryption,
    // Both halves are required: the query type has to exist on the server AND the driver has to be
    // able to analyse a query against it, or declaring it buys an index nothing can use.
    qeSubstring: automaticEncryption && atLeast(version, 9, 0),
    qeRange: automaticEncryption && atLeast(version, 8, 0),
    changeStreams: replicaSet,
    transactions: replicaSet,
    timeSeries: atLeast(version, 5, 0),
    timeSeriesExpiry: atLeast(version, 5, 0),
    atlasSearch: type === 'atlas',
    serverAuditLog: type !== 'ce',
  };
}

function declaredDeployment(): MongoDeployment {
  const type = parseDeploymentType(config.mongodb.type);
  return {
    type,
    version: parseVersion(config.mongodb.version || DEFAULT_VERSION),
    source: 'declared',
    // Not knowable without a connection. Atlas is always a replica set; a self-managed deployment may
    // be a standalone, and assuming otherwise would promise a change stream that cannot start.
    replicaSet: type === 'atlas',
  };
}

// The resolved answer, shared by every caller. Declared until a probe replaces it, so the synchronous
// callers (the encrypted-fields builder, setup's preflight) always have one.
let resolved: MongoDeployment = declaredDeployment();

export function deployment(): MongoDeployment {
  return resolved;
}

export function capabilities(): MongoCapabilities {
  return capabilitiesOf(resolved);
}

/** Re-reads the environment. For a configuration reload, and for tests. */
export function resetDeployment(): MongoDeployment {
  resolved = declaredDeployment();
  return resolved;
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

export function classifyProbe(build: BuildInfo, hello: HelloInfo, uri: string): MongoDeployment {
  const version = parseVersion(build.version ?? DEFAULT_VERSION);
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
 * Probes the live deployment and makes it the resolved answer.
 *
 * Never throws. A cluster that refuses `buildInfo` to this user is a permission posture, not a
 * reason to stop: the declared values stay in force and the failure is reported.
 */
export async function detectDeployment(client: MongoClient): Promise<MongoDeployment> {
  const declared = declaredDeployment();
  try {
    const admin = client.db('admin');
    const build = await admin.command({ buildInfo: 1 }) as BuildInfo;
    const hello = await admin.command({ hello: 1 }) as HelloInfo;
    const actual = classifyProbe(build, hello, config.mongodb.uri);
    resolved = { ...actual, mismatch: describeMismatch(declared, actual) };
  } catch (err) {
    resolved = {
      ...declared,
      mismatch: `the deployment could not be probed (${err instanceof Error ? err.message : String(err)}); `
        + 'the declared MONGODB_TYPE and MONGODB_VERSION are in force',
    };
  }
  return resolved;
}

export function describeDeployment(current: MongoDeployment = resolved): string {
  const topology = current.replicaSet ? 'replica set' : 'standalone';
  return `${current.type} ${current.version.raw} (${topology}, ${current.source})`;
}

/**
 * The capability lines for the startup and setup reports, warning on anything this codebase needs
 * and this deployment cannot give it.
 */
export function capabilityFindings(current: MongoDeployment = resolved): Array<{ text: string; warn: boolean }> {
  const caps = capabilitiesOf(current);
  const findings: Array<{ text: string; warn: boolean }> = [];

  if (!caps.automaticEncryption) {
    findings.push({
      warn: true,
      text: current.type === 'ce'
        ? 'Community Edition cannot perform automatic encryption: every read of an encrypted '
          + 'principal field will fail. GIAM needs Atlas or Enterprise Advanced.'
        : `server ${current.version.raw} predates Queryable Encryption (7.0+); encrypted collections cannot be created`,
    });
  }
  if (caps.automaticEncryption && !caps.qeSubstring) {
    findings.push({
      warn: false,
      text: `substring search on encrypted names needs server 9.0+ (this is ${current.version.raw}); `
        + 'names fall back to equality, still encrypted and still exactly searchable',
    });
  }
  if (!caps.changeStreams) {
    findings.push({
      warn: false,
      text: 'no replica set: the live-session cache cannot start, so revocation relies on the '
        + 'authoritative read and the token lifetime',
    });
  }
  if (!caps.timeSeriesExpiry) {
    findings.push({
      warn: true,
      text: `server ${current.version.raw} has no time series expiry; the audit trail cannot enforce its retention`,
    });
  }
  if (current.mismatch) findings.push({ warn: true, text: current.mismatch });
  return findings;
}
