import { Db } from 'mongodb';
import { trailHealth } from '../../modules/audit/services/securityEvent.service';
import { existsSync } from 'fs';
import { describeDeployment, capabilityFindings, capabilities } from '../../vendors/mongodb/deployment';
import { config, keyVaultNamespace, realmIssuer } from '../../config';
import { REALM_COLLECTION, PRINCIPAL_COLLECTION, KEY_COLLECTION } from '../models/collections';

// What GIAM reports about itself at boot, so "is it working" is answerable from the log alone.
// Every failure mode that costs time on this platform shows up here: a wrong crypt_shared path, a
// vault pointed somewhere unexpected, an unseeded database, a realm with no published signing key.
// Each of those otherwise surfaces as a generic 503 or a blanket 401.
//
// Nothing secret is printed. A connection string is shown with its credentials removed, and a key is
// reported by its custody mode, never by its value.

export interface StartupLine {
  label: string;
  value: string;
  // 'warn' marks something that will break a call later, so it stands out in a wall of INFO lines.
  level?: 'info' | 'warn';
}

export function redactMongoUri(uri: string): string {
  if (!uri) return '(not set)';
  // Hand-parsed rather than via URL: a mongodb+srv string with a comma separated host list is not a
  // valid WHATWG URL, and a throw here would hide the whole report.
  const match = /^(mongodb(?:\+srv)?:\/\/)([^@/]*@)?(.*)$/i.exec(uri);
  if (!match) return '(unparseable connection string)';
  const [, scheme, userinfo, rest] = match;
  if (!userinfo) return `${scheme}${rest}`;
  const user = userinfo.slice(0, -1).split(':')[0];
  return `${scheme}${user ? `${user}:***@` : '***@'}${rest}`;
}

function cryptSharedLine(): StartupLine {
  const path = config.mongodb.cryptSharedLibPath;
  if (!path) return { label: 'crypt_shared', value: '(not set) encrypted reads will fail', level: 'warn' };
  const present = existsSync(path);
  return {
    label: 'crypt_shared',
    value: present ? path : `${path} (MISSING: the whole connection fails and reads as a plain outage)`,
    level: present ? 'info' : 'warn',
  };
}

/** The static half: process, bindings and configuration. Needs no database. */
export function configurationReport(): StartupLine[] {
  return [
    { label: 'environment', value: `${config.nodeEnv}, node ${process.version}` },
    { label: 'instance', value: config.keys.instanceId },
    { label: 'listening', value: `http://${config.server.host}:${config.server.port}` },
    { label: 'private URL', value: config.server.baseUrl },
    {
      label: 'public URL',
      value: config.server.publicUrl || '(none) this deployment does not publish GIAM',
    },
    { label: 'console', value: config.server.frontendUrl },
    { label: 'swagger', value: `${config.server.baseUrl}/doc` },
    { label: 'health', value: `${config.server.baseUrl}/api/v1/system/health` },
    { label: 'posture', value: `${config.server.baseUrl}/api/v1/admin/posture` },
    {
      label: 'issuer pattern',
      value: `${realmIssuer('<realm>')} (composed per token from ${config.server.publicUrl ? 'GIAM_PUBLIC_URL' : 'GIAM_BASE_URL, no public URL set'}, never stored)`,
    },
    { label: 'database', value: config.mongodb.dbName },
    { label: 'cluster', value: redactMongoUri(config.mongodb.uri) },
    // Its own vault with its own keys. Sharing the applications' vault would defeat the extraction.
    { label: 'key vault', value: `${keyVaultNamespace()} (GIAM's own, GIAM's own DEKs)` },
    cryptSharedLine(),
    { label: 'deployment', value: describeDeployment() },
    ...capabilityFindings().map((finding) => ({
      label: 'compatibility',
      value: finding.text,
      level: (finding.warn ? 'warn' : 'info') as 'warn' | 'info',
    })),
    {
      label: 'QE text search',
      value: capabilities().qeSubstring ? 'on, substring' : 'off, names degrade to equality',
    },
    { label: 'key custody', value: `${config.keys.provider}, ${config.keys.replicas} declared replica(s)` },
    { label: 'event bus', value: `${config.app.eventBusEngine}, own store` },
    {
      label: 'admin surface',
      value: config.app.adminToken ? 'credential configured' : 'no credential: /admin refuses every call',
      level: config.app.adminToken ? 'info' : 'warn',
    },
  ];
}

/** The live half: what the database actually holds. Reported as a warning when it is not usable. */
export async function readinessReport(db: Db | undefined, dbError: string | null): Promise<StartupLine[]> {
  if (dbError !== null || !db) {
    return [{ label: 'directory', value: `UNAVAILABLE: ${dbError ?? 'no database handle'}`, level: 'warn' }];
  }

  const lines: StartupLine[] = [];
  try {
    const started = Date.now();
    await db.command({ ping: 1 });
    lines.push({ label: 'directory', value: `reachable in ${Date.now() - started}ms` });
  } catch (err) {
    return [{ label: 'directory', value: `ping failed: ${err instanceof Error ? err.message : String(err)}`, level: 'warn' }];
  }

  /**
   * The audit trail's own health. PCI DSS 10.7 requires that a failure to log be DETECTED.
   *
   * Reported before the record counts below, because a deployment whose trail is dropping writes has
   * a problem that outranks how many realms it has. `warn` and not a hard failure: the trail is
   * deliberately non-blocking, so a degraded trail is a serving deployment that an operator must
   * know about rather than one that should stop.
   */
  const trail = trailHealth();
  lines.push(trail.healthy
    ? { label: 'audit trail', value: `${trail.written} event(s) written, no failures` }
    : {
      label: 'audit trail',
      value: `DEGRADED: ${trail.failed} write(s) lost, last at ${trail.lastFailureAt}. Evidence is incomplete`,
      level: 'warn',
    });

  try {
    const realms = await db.collection(REALM_COLLECTION)
      .find({}, { projection: { _id: 0, realmId: 1, name: 1, enabled: 1, issuer: 1 } })
      .toArray() as Array<{ name?: string; enabled?: boolean; issuer?: string }>;
    // A stored issuer is from a release that persisted it. It is ignored, and naming it explains a
    // database that still shows another deployment's address.
    const legacy = realms.filter((r) => r.issuer);
    if (legacy.length > 0) {
      lines.push({
        label: 'realms',
        value: `${legacy.length} realm(s) still carry a stored issuer (${legacy.map((r) => r.issuer).join(', ')}); it is ignored, and the next seed removes it`,
        level: 'warn',
      });
    }
    lines.push(realms.length > 0
      ? { label: 'realms', value: realms.map((r) => `${r.name}${r.enabled === false ? ' (disabled)' : ''}`).join(', ') }
      // With no realm nothing can be issued, and the failure reads as a token bug rather than empty data.
      : { label: 'realms', value: 'none: nothing can authenticate. Run setup:seed', level: 'warn' });

    const identities = await db.collection(PRINCIPAL_COLLECTION).estimatedDocumentCount();
    lines.push({
      label: 'identities',
      value: identities > 0 ? `${identities} principal(s)` : 'none: the database is not seeded',
      level: identities > 0 ? 'info' : 'warn',
    });

    // A realm with no published key can mint nothing and verify nothing.
    //
    // Reported as two numbers because they answer different questions and only one of them is a
    // health check. Signing keys are what this replica can mint with; published keys include every
    // key still trusted for verification, which legitimately outnumbers them after a rotation or a
    // scale-down. A single count of everything `active` conflated the two and read as a leak.
    const signingKeys = await db.collection(KEY_COLLECTION).countDocuments({
      status: 'active',
      signingEligible: true,
      instanceId: config.keys.instanceId,
    });
    const published = await db.collection(KEY_COLLECTION).countDocuments({ status: 'active' });
    lines.push({
      label: 'published keys',
      value: published > 0
        ? `${signingKeys} signing here, ${published} trusted for verification`
        : 'none active: no token can be signed or verified',
      level: published > 0 ? 'info' : 'warn',
    });
  } catch (err) {
    lines.push({
      label: 'readiness',
      value: `could not be read: ${err instanceof Error ? err.message : String(err)}`,
      level: 'warn',
    });
  }
  return lines;
}

export function formatReport(lines: StartupLine[]): string[] {
  const width = Math.max(...lines.map((line) => line.label.length));
  return lines.map((line) => `  ${line.level === 'warn' ? '!' : '·'} ${line.label.padEnd(width)}  ${line.value}`);
}
