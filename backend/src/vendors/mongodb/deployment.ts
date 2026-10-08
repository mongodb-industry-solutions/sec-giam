// What KIND of MongoDB GIAM is talking to, and what that deployment can actually do.
//
// Every feature this system depends on that is not universal (Queryable Encryption, the substring
// query type, change streams, time series expiry, Atlas Search) is gated HERE, in one place, rather
// than behind a hand-managed boolean per feature. This used to be GIAM's OWN reimplementation of
// that idea; it is now a thin wrapper around `@leafypay/mongo-compat`, the same package the PSP and
// bankcore use, vendored into this repo at `packages/mongo-compat` and kept byte-for-byte identical
// to theirs by hand (there is no registry: the copies ARE the distribution mechanism).
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
//
// Every exported name and signature here is unchanged from GIAM's own former implementation, so
// nothing downstream (posture.service.ts, plugins/mongodb.ts, startupReport.ts,
// encryptedFieldsMaps.ts, the setup/seed scripts, operations.controller.ts) had to change.

import type { MongoClientLike, MongoDeployment, MongoCapabilities } from '@leafypay/mongo-compat';
import {
  parseDeploymentType, declaredDeployment as sharedDeclaredDeployment,
  capabilitiesOf, detectDeployment as sharedDetectDeployment, describeDeployment as sharedDescribeDeployment,
  capabilityFindings as sharedCapabilityFindings,
} from '@leafypay/mongo-compat';
import { config } from '../../config';

export type { MongoDeploymentType, MongoVersion, MongoDeployment, MongoCapabilities } from '@leafypay/mongo-compat';
export { parseVersion, atLeast } from '@leafypay/mongo-compat';

function declaredDeployment(): MongoDeployment {
  const type = parseDeploymentType(config.mongodb.type);
  // Not knowable without a connection. Atlas is always a replica set; a self-managed deployment may
  // be a standalone, and assuming otherwise would promise a change stream that cannot start.
  return { ...sharedDeclaredDeployment(type, config.mongodb.version), replicaSet: type === 'atlas' };
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

/**
 * Probes the live deployment and makes it the resolved answer.
 *
 * Never throws. A cluster that refuses `buildInfo` to this user is a permission posture, not a
 * reason to stop: the declared values stay in force and the failure is reported.
 */
export async function detectDeployment(client: MongoClientLike): Promise<MongoDeployment> {
  resolved = await sharedDetectDeployment(client, declaredDeployment());
  return resolved;
}

export function describeDeployment(current: MongoDeployment = resolved): string {
  return sharedDescribeDeployment(current);
}

/**
 * The capability lines for the startup and setup reports, warning on anything this codebase needs
 * and this deployment cannot give it.
 */
export function capabilityFindings(current: MongoDeployment = resolved): Array<{ text: string; warn: boolean }> {
  return sharedCapabilityFindings(current);
}
