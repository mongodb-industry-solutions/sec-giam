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
  PRINCIPAL_COLLECTION, DELEGATION_COLLECTION, GRANT_COLLECTION,
  AUDIT_COLLECTION,
} from '../../../backend/src/shared/models/collections';
import {
  MAX_ROLE_HOLDINGS, isHoldingActive,
} from '../../../backend/src/modules/directory/models/principal.model';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';

const SRC = resolve(__dirname, '../../../backend/src');

/** Every .ts file under backend/src, with the directories a rule exempts removed. */
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
  it('folds the agent definition onto the principal that acts, not beside it', () => {
    // v40 reverses the v39 decision deliberately. An agent is a subject that acts, so it belongs in
    // the one register of subjects, carried as an optional sub document exactly as workload
    // attestation already is. A separate collection held half a subject whose other half was in the
    // principal record. The approved-versus-ran distinction is carried by the audit record, which
    // names both the principal and the configuration digest in force at the time.
    const names = GIAM_COLLECTIONS.map((s) => s.name);
    expect(names).not.toContain('agent');
    expect(names).toContain(PRINCIPAL_COLLECTION);
  });

  it('folds a delegation into the grant that carries its purpose', () => {
    // Also a reversal. A delegation IS a grant with a purpose, constraints and an expiry: the same
    // record with three more fields, not a second concept. Keeping both invited the question of
    // which one a given consent lived in.
    const names = GIAM_COLLECTIONS.map((s) => s.name);
    expect(names).not.toContain(DELEGATION_COLLECTION);
    expect(names).toContain(GRANT_COLLECTION);
  });

  it('caps the embedded role array, and declares no TTL index that would expire its holder', () => {
    // Embedding is only safe while the array is bounded, so the bound is asserted rather than
    // described. The second half matters more: a TTL index expires whole DOCUMENTS and never array
    // elements, so a TTL on the principal's own `expiresAt` would delete the SUBJECT rather than the
    // lapsed holding. That is why expiry is filtered at read time and swept for hygiene only.
    expect(MAX_ROLE_HOLDINGS).toBeGreaterThan(0);
    expect(MAX_ROLE_HOLDINGS).toBeLessThanOrEqual(200);

    const principalTtl = plannedIndexes().filter(
      (plan) => plan.collection === PRINCIPAL_COLLECTION
        && plan.options.expireAfterSeconds !== undefined,
    );
    expect(principalTtl, 'a TTL index on principal would expire the subject, not the role').toEqual([]);
  });

  it('indexes the inverse role question, because certification and revocation both ask it', () => {
    // "Who holds role X" is the query embedding makes expensive, so it is the one that must be
    // indexed. Multikey over the embedded array, and leading with the partition key.
    const inverse = plannedIndexes().find(
      (plan) => plan.collection === PRINCIPAL_COLLECTION
        && Object.keys(plan.keys as Record<string, unknown>).join(',') === 'realmId,roles.roleId',
    );
    expect(inverse, 'no multikey index on {realmId, roles.roleId}').toBeTruthy();
  });

  it('holds a lapsed or unapproved role as granting nothing', () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const future = new Date(Date.now() + 60_000).toISOString();
    // Read-time filtering is the correctness mechanism, so it is asserted directly rather than
    // through whatever happens to call it.
    expect(isHoldingActive({ roleId: 'r', grantedAt: past })).toBe(true);
    expect(isHoldingActive({ roleId: 'r', grantedAt: past, expiresAt: future })).toBe(true);
    expect(isHoldingActive({ roleId: 'r', grantedAt: past, expiresAt: past })).toBe(false);
    // Fails closed: an elevation nobody has approved yet grants nothing, whatever its expiry says.
    expect(isHoldingActive({ roleId: 'r', grantedAt: past, expiresAt: future, pendingApproval: true })).toBe(false);
  });

  it('keeps the tenant partition as a field rather than as a collection', () => {
    // v40: no tenant exists distinct from its realm, so the collection is paid-for complexity.
    // tenantId stays on every scoped record, which is what preserves the partition key, the index
    // prefix and the option of a real second tenant later.
    expect(GIAM_COLLECTIONS.map((s) => s.name)).not.toContain('tenant');
    expect(scopedCollections().length).toBeGreaterThan(0);
  });

  it('stores security events in a time series rather than an ordinary collection', () => {
    const spec = GIAM_COLLECTIONS.find((s) => s.name === AUDIT_COLLECTION);
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

  /**
   * v41 D44. The same rule, over the SOURCE and not only over the registry.
   *
   * The check above reads `GIAM_COLLECTIONS` alone, so a constant in a service, a claim name or an
   * authorization detail type could say `payment` and nothing fired. That is the narrowest possible
   * reading of a rule the project states broadly, and it is the gap through which v41 nearly shipped
   * a built-in `payment_initiation` authorization detail type.
   *
   * `vendors/seed/` is exempt, as it is for the consumer-name check above and for the same reason:
   * seed data legitimately CREATES the records that represent a deployment's business.
   *
   * `transaction` is NOT in the pattern, because `transactionId` names a delegation's task binding,
   * which is a generic concept the grant model owns rather than an industry's word.
   */
  it('names no single industry anywhere in the source, not only in the registry', () => {
    const industry = /\b(payment|payments|card|pan|iban|merchant|ledger|settlement)\b/i;
    const offenders: string[] = [];
    for (const file of sourceFiles(['vendors/seed/'])) {
      const match = stripComments(file.text).match(industry);
      if (match) offenders.push(`${file.path} says "${match[0]}"`);
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });
});
