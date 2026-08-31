// v39 P0.6: the invariants that cost little now and are expensive to retrofit.
//
// Each of these is here because fixing it later means touching every query, every record or every
// deployment. They are asserted against the source and the declared model rather than against a
// running database, so they fail in CI on the commit that breaks them.
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'fs';
import { resolve, relative, sep } from 'path';
import {
  GIAM_COLLECTIONS, scopedCollections,
  IDENTITY_COLLECTION, AGENT_COLLECTION, DELEGATION_COLLECTION, GRANT_COLLECTION,
  SECURITY_EVENT_COLLECTION, TENANT_COLLECTION,
} from '../../../../giam/backend/src/shared/models/collections';
import { plannedIndexes } from '../../../../giam/backend/src/vendors/setup/createIndexes';

const SRC = resolve(__dirname, '../../../../giam/backend/src');

/** Every .ts file under giam/backend/src, with the directories a rule exempts removed. */
function sourceFiles(exclude: string[] = []): Array<{ path: string; text: string }> {
  const found: Array<{ path: string; text: string }> = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = resolve(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.endsWith('.ts')) continue;
      const rel = relative(SRC, full).split(sep).join('/');
      if (exclude.some((prefix) => rel.startsWith(prefix))) continue;
      found.push({ path: rel, text: readFileSync(full, 'utf8') });
    }
  };
  walk(SRC);
  return found;
}

/** Comments carry rationale, and a rationale may legitimately name what the rule forbids in code. */
function stripComments(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
}

/**
 * Import lines, removed before a rule looks at the code.
 *
 * A shared package is named after the platform that owns it, and importing one is reuse rather than a
 * branch. The rule this serves forbids GIAM DECIDING something because of who the consumer is; it does
 * not forbid depending on a package whose name happens to contain a consumer's.
 */
function stripImports(text: string): string {
  return text
    .split('\n')
    // Both shapes: a single-line import, and the closing line of a multi-line one.
    .filter((line) => !/^\s*(import|export)\b.*\bfrom\s+['"]/.test(line)
      && !/^\s*\}?\s*from\s+['"]/.test(line)
      && !/\brequire\s*\(/.test(line))
    .join('\n');
}

describe('v39 P0.6: every record is partitioned from its first version', () => {
  it('marks every domain collection scoped, and only infrastructure unscoped', () => {
    const unscoped = GIAM_COLLECTIONS.filter((spec) => !spec.scoped);
    for (const spec of unscoped) {
      // A domain collection that is not partitioned cannot be made multi-tenant without touching
      // every query on it, and its shard key cannot be changed after the fact.
      expect(spec.kind, `${spec.name} is unscoped but is not infrastructure`).toBe('infrastructure');
    }
    expect(scopedCollections().length).toBeGreaterThan(0);
  });

  it('leads every compound index on a scoped collection with realmId', () => {
    // The partition key is `{realmId, tenantId}` and it is the shard key if this ever shards. An
    // index that does not lead with it cannot serve a tenant-scoped query.
    const offenders: string[] = [];
    for (const plan of plannedIndexes()) {
      const spec = GIAM_COLLECTIONS.find((s) => s.name === plan.collection);
      if (!spec?.scoped) continue;
      const keys = Object.keys(plan.keys as Record<string, unknown>);
      if (keys.length < 2) continue;
      if (keys[0] !== 'realmId') offenders.push(`${plan.collection}.${plan.options.name} leads with ${keys[0]}`);
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });

  it('keeps a globally unique identifier globally unique, not unique per realm', () => {
    // The other half of the same rule. A token jti or a key id is resolved WITHOUT a realm in hand,
    // because the question a verifier asks is which realm this thing belongs to.
    const globalUniques = plannedIndexes().filter((plan) => {
      const keys = Object.keys(plan.keys as Record<string, unknown>);
      return plan.options.unique && keys.length === 1 && keys[0] !== 'realmId';
    });
    expect(globalUniques.length).toBeGreaterThan(0);
    for (const plan of globalUniques) {
      expect(Object.keys(plan.keys as Record<string, unknown>)).toHaveLength(1);
    }
  });

  it('declares a TTL index for every collection the registry marks ephemeral', () => {
    // Expiry is the database's job. A cleanup job is a thing that fails silently.
    for (const spec of GIAM_COLLECTIONS.filter((s) => s.ttlField)) {
      const ttl = plannedIndexes().find(
        (plan) => plan.collection === spec.name && plan.options.expireAfterSeconds !== undefined,
      );
      expect(ttl, `${spec.name} declares ttlField "${spec.ttlField}" but has no TTL index`).toBeTruthy();
    }
  });
});

describe('v39 P0.6: the four doors that cannot be reopened cheaply', () => {
  it('keeps a logical agent distinct from the runtime workload that executes it', () => {
    // One approved agent has many workloads over its life. Collapsing them means an audit record can
    // say what was approved or what ran, never both.
    const names = GIAM_COLLECTIONS.map((s) => s.name);
    expect(names).toContain(AGENT_COLLECTION);
    expect(names).toContain(IDENTITY_COLLECTION);
  });

  it('keeps a delegation distinct from an OAuth grant', () => {
    // A grant is consent to a client's scopes. A delegation is a person authorising an agent to act,
    // which is purpose bound, constrained, time limited and separately revocable.
    const names = GIAM_COLLECTIONS.map((s) => s.name);
    expect(names).toContain(DELEGATION_COLLECTION);
    expect(names).toContain(GRANT_COLLECTION);
    expect(DELEGATION_COLLECTION).not.toBe(GRANT_COLLECTION);
  });

  it('models a tenant as a boundary inside a realm rather than as another realm', () => {
    expect(GIAM_COLLECTIONS.map((s) => s.name)).toContain(TENANT_COLLECTION);
  });

  it('stores security events in a time series rather than an ordinary collection', () => {
    const spec = GIAM_COLLECTIONS.find((s) => s.name === SECURITY_EVENT_COLLECTION);
    // It cannot be converted in place, so getting it wrong once is permanent until a drop.
    expect(spec?.kind).toBe('timeseries');
  });
});

describe('v39 P0.6: no capability is gated by environment', () => {
  it('never asks which environment it is running in', () => {
    // Hardening is configuration. A weaker configuration warns and is documented; it does not change
    // which code path runs, and nothing is switched off because a variable says "development".
    const forbidden = [
      /\bNODE_ENV\b\s*[=!]==?/,
      /nodeEnv\s*[=!]==?/,
      /\bis(Production|Development|Staging|Prod|Dev)\b/,
      /['"`](production|development|staging)['"`]\s*[=!]==?/,
    ];
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const code = stripComments(file.text);
      for (const pattern of forbidden) {
        if (pattern.test(code)) offenders.push(`${file.path} matches ${pattern}`);
      }
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });
});

describe('v39 P0.6: GIAM carries no consumer and no industry vocabulary', () => {
  it('names no consumer application in its logic', () => {
    // Realms, resource servers, permission catalogs and clients are the only way a consumer is
    // represented. Seed data legitimately CREATES those records, which is why it is exempt; a branch
    // in a service naming one is the first symptom of the product collapsing back into an
    // application's auth service.
    const consumers = /\b(leafypay|bankcore|leafywallet)\b/i;
    const offenders = sourceFiles(['vendors/seed/'])
      .filter((file) => consumers.test(stripImports(stripComments(file.text))))
      .map((file) => file.path);
    expect(offenders, `names a consumer: ${offenders.join(', ')}`).toEqual([]);
  });

  it('uses security-standard names rather than the platform domain vocabulary', () => {
    const forbidden = [
      /\bbianServiceDomain\b/,
      /\bbianControlRecordType\b/,
      /\b\w+InstanceReference\b/,
      /\bparty[A-Z]\w*/,
    ];
    const offenders: string[] = [];
    for (const file of sourceFiles()) {
      const code = stripComments(file.text);
      for (const pattern of forbidden) {
        if (pattern.test(code)) offenders.push(`${file.path} matches ${pattern}`);
      }
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });

  it('names no financial concept in its model', () => {
    // GIAM is reused outside financial services. A collection or field naming a payment concept is
    // what would make that impossible to claim.
    const financial = /\b(payment|card|pan|iban|merchant|ledger|transaction|settlement)\b/i;
    const offenders = GIAM_COLLECTIONS
      .filter((spec) => financial.test(spec.name) || financial.test(spec.purpose))
      .map((spec) => spec.name);
    expect(offenders, `financial vocabulary in: ${offenders.join(', ')}`).toEqual([]);
  });
});
