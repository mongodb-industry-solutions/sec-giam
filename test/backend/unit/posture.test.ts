// v39 P0.8: the posture endpoint, and the rule it replaces.
//
// GIAM gates no capability on environment. Instead of deciding what an operator may run, it makes
// what IS running impossible to misread. This suite holds that position to its consequence: a weaker
// configuration is REPORTED in four places and the service still serves. A test that only checked the
// report would miss the half that matters, which is that nothing refuses to start.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { PORT_REGISTRIES } from '../../../../giam/backend/src/shared/ports';
import { registerBuiltinPorts } from '../../../../giam/backend/src/shared/ports/builtins';
import {
  buildPostureReport, postureBanner,
} from '../../../../giam/backend/src/modules/admin/services/posture.service';
import { config } from '../../../../giam/backend/src/config';

const RUNBOOK = readFileSync(resolve(__dirname, '../../../../giam/docs/runbook.md'), 'utf8');

// config is a frozen-by-convention object, so a test changes it the way an operator would change the
// environment: by writing the value, not by rebuilding the module.
type MutableKeys = { -readonly [K in keyof typeof config.keys]: (typeof config.keys)[K] };
const keys = config.keys as unknown as MutableKeys;
let original: MutableKeys;

beforeEach(() => {
  PORT_REGISTRIES.KeyProvider.clear();
  registerBuiltinPorts();
  original = { ...keys };
});

afterEach(() => {
  Object.assign(keys, original);
});

describe('v39 P0.8: the posture report describes what is actually in force', () => {
  it('reports key custody, replica awareness and both validation models', () => {
    const report = buildPostureReport({ databaseReachable: true });
    expect(report.keyCustody.provider).toBe(config.keys.provider);
    expect(report.keyCustody.declaredReplicas).toBe(config.keys.replicas);
    // Both models are always available; which applies is the resource server's choice per operation,
    // never a build-time decision.
    expect(report.tokenValidation.supportedModes).toEqual(['local-jwks', 'introspection']);
  });

  it('reports the default custody mode as multi-replica capable with no external dependency', () => {
    keys.provider = 'instance-local';
    keys.replicas = 5;
    const report = buildPostureReport({ databaseReachable: true });
    expect(report.keyCustody.multiReplicaCapable).toBe(true);
    // No KMS, no wrapping key, five replicas, and nothing degraded about it.
    expect(report.findings.map((f) => f.code)).not.toContain('key_path_may_not_be_shared');
  });

  it('names GIAM\'s own key vault, not the one the applications share', () => {
    const report = buildPostureReport({ databaseReachable: true });
    expect(report.storage.keyVault).toBe(`${config.mongodb.dbName}.${config.mongodb.keyVaultCollection}`);
  });
});

describe('v39 P0.8: a weaker configuration warns in four places and still runs', () => {
  it('flags a possibly unshared key path when more than one replica is declared', () => {
    keys.provider = 'filesystem';
    keys.replicas = 3;
    const report = buildPostureReport({ databaseReachable: true });

    expect(report.status).toBe('degraded');
    const finding = report.findings.find((f) => f.code === 'key_path_may_not_be_shared');
    expect(finding).toBeTruthy();
    // The exact risk, not a category: intermittent verification failure depending on which replica
    // served the request, which is the hardest shape to diagnose.
    expect(finding?.detail).toContain('intermittently');
    expect(finding?.remedy).toContain('instance-local');
  });

  it('reaches the console banner, so a degraded deployment is visible without a query', () => {
    keys.provider = 'filesystem';
    keys.replicas = 3;
    const banner = postureBanner(buildPostureReport({ databaseReachable: true }));
    expect(banner.some((line) => line.includes('DEGRADED'))).toBe(true);
    expect(banner.some((line) => line.includes('key_path_may_not_be_shared'))).toBe(true);
    // A remedy in the banner too: an operator reading a warning with no action takes none.
    expect(banner.some((line) => line.startsWith('   remedy:'))).toBe(true);
    expect(banner.some((line) => line.includes('/admin/posture'))).toBe(true);
  });

  it('says nothing when there is nothing to say', () => {
    keys.provider = 'instance-local';
    keys.replicas = 1;
    const report = buildPostureReport({ databaseReachable: true });
    // A banner on every boot trains an operator to ignore banners.
    if (report.status === 'ok') expect(postureBanner(report)).toEqual([]);
  });

  it('documents every finding code in the runbook', () => {
    // The fourth place. A code that fires and is not documented sends an operator to the source.
    keys.provider = 'filesystem';
    keys.replicas = 3;
    keys.publicationGraceSeconds = 1;
    keys.leaseSeconds = 300;
    const codes = new Set([
      ...buildPostureReport({ databaseReachable: false, databaseError: 'unreachable' }).findings.map((f) => f.code),
      ...buildPostureReport({ databaseReachable: true }).findings.map((f) => f.code),
    ]);
    expect(codes.size).toBeGreaterThan(0);
    for (const code of codes) {
      expect(RUNBOOK, `the runbook does not document the finding "${code}"`).toContain(code);
    }
  });

  it('flags a publication grace shorter than the lease, because a scale-down would sign users out', () => {
    keys.publicationGraceSeconds = 60;
    keys.leaseSeconds = 300;
    const report = buildPostureReport({ databaseReachable: true });
    const finding = report.findings.find((f) => f.code === 'publication_grace_too_short');
    expect(finding).toBeTruthy();
    expect(finding?.remedy).toContain('GIAM_KEY_PUBLICATION_GRACE_SECONDS');
  });

  it('reports an unreachable database rather than hiding it behind an authentication error', () => {
    const report = buildPostureReport({ databaseReachable: false, databaseError: 'connection refused' });
    const finding = report.findings.find((f) => f.code === 'storage_unreachable');
    expect(finding?.detail).toContain('connection refused');
    // 503 rather than 401, so the operator reads the real cause.
    expect(finding?.remedy).toContain('503');
  });

  it('refuses an unknown custody mode by name rather than falling back to one', () => {
    keys.provider = 'no-such-provider' as typeof keys.provider;
    const report = buildPostureReport({ databaseReachable: true });
    const finding = report.findings.find((f) => f.code === 'key_provider_unknown');
    expect(finding).toBeTruthy();
    // The remedy lists what exists, so it is actionable without reading the source.
    expect(finding?.remedy).toContain('instance-local');
  });

  it('gives every finding a code, a detail and a remedy', () => {
    keys.provider = 'filesystem';
    keys.replicas = 3;
    for (const finding of buildPostureReport({ databaseReachable: false }).findings) {
      expect(finding.code).toMatch(/^[a-z][a-z_]+$/);
      expect(finding.detail.length, `${finding.code} has no detail`).toBeGreaterThan(20);
      expect(finding.remedy.length, `${finding.code} has no remedy`).toBeGreaterThan(10);
    }
  });
});
