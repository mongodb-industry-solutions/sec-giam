// v40 P11.12: constraint 3, asserted rather than reviewed.
//
// Every rule here was checked by hand when the ADR was written. A rule checked by hand is a rule
// that holds until the next person is in a hurry, so each one is a test. The point is not that the
// model is currently correct; it is that a change breaking one of these fails in CI rather than in
// somebody's judgement six months later.
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'fs';
import { resolve, relative, sep } from 'path';
import { GIAM_COLLECTIONS, scopedCollections } from '../../../backend/src/shared/models/collections';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';
import { MAX_ROLE_HOLDINGS } from '../../../backend/src/modules/directory/models/principal.model';
import { MAX_ACTIVE_CLIENT_SECRETS } from '../../../backend/src/modules/directory/models/credential.model';

const SRC = resolve(__dirname, '../../../backend/src');

function sourceFiles(): Array<{ path: string; text: string }> {
  const found: Array<{ path: string; text: string }> = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = resolve(dir, entry);
      if (statSync(full).isDirectory()) { walk(full); continue; }
      if (!entry.endsWith('.ts')) continue;
      found.push({ path: relative(SRC, full).split(sep).join('/'), text: readFileSync(full, 'utf8') });
    }
  };
  walk(SRC);
  return found;
}

describe('P11.12: exactly thirteen collections, and audit is the only time series', () => {
  it('registers thirteen, which is the number the whole refactor is about', () => {
    expect(GIAM_COLLECTIONS).toHaveLength(13);
  });

  it('makes audit the ONLY time series', () => {
    /**
     * Append-only evidence queried by range belongs in a time series. Everything else does not, and
     * the distinction is not cosmetic: a time series accepts no unique index, so putting keyed data
     * in one silently gives up the constraint that made it keyed.
     *
     * `eventbus` is the case that proves the rule. It looks like append-only telemetry and is NOT a
     * time series, because it needs `eventId` unique for deduplication.
     */
    const series = GIAM_COLLECTIONS.filter((spec) => spec.kind === 'timeseries').map((spec) => spec.name);
    expect(series).toEqual(['audit']);
  });

  it('declares no unique index on the time series, which would silently not exist', () => {
    const onSeries = plannedIndexes().filter(
      (plan) => plan.collection === 'audit' && plan.options.unique,
    );
    expect(onSeries, 'a time series does not support a unique index').toEqual([]);
  });

  it('keeps eventbus out of the time series, because it needs uniqueness', () => {
    const eventbus = GIAM_COLLECTIONS.find((spec) => spec.name === 'eventbus');
    expect(eventbus?.kind).toBe('infrastructure');
  });
});

describe('P11.12: every compound index on a scoped collection leads with realmId', () => {
  it('holds for all of them, with no exception list', () => {
    // The claim the header used to get wrong. Asserted here so it cannot drift again.
    const scoped = new Set(scopedCollections().map((spec) => spec.name));
    const offenders: string[] = [];
    for (const plan of plannedIndexes()) {
      if (!scoped.has(plan.collection)) continue;
      const keys = Object.keys(plan.keys as Record<string, unknown>);
      if (keys.length < 2) continue;
      if (keys[0] !== 'realmId') offenders.push(`${plan.collection}.${plan.options.name} leads ${keys[0]}`);
    }
    expect(offenders, offenders.join('; ')).toEqual([]);
  });

  it('keeps realmId a prefix of the shard key, which is what makes that sufficient', () => {
    // `{realmId, tenantId}` is the shard key and `realmId` is its prefix, so a query narrowing by
    // realm alone is still targetable. That is the whole reason the pair is not required in every
    // index, and it is worth asserting that the partition field is on every scoped record.
    for (const spec of scopedCollections()) {
      expect(spec.scoped, `${spec.name} must carry realmId and tenantId`).toBe(true);
    }
  });

  it('allows a global unique only on an identifier resolved without a realm', () => {
    // A key id or a subject id is looked up when the question IS which realm it belongs to, so it
    // cannot be scoped by one. Every other unique index is per realm.
    const globalUniques = plannedIndexes().filter((plan) => {
      const keys = Object.keys(plan.keys as Record<string, unknown>);
      return plan.options.unique && keys.length === 1 && keys[0] !== 'realmId';
    });
    for (const plan of globalUniques) {
      const field = Object.keys(plan.keys as Record<string, unknown>)[0];
      // An identifier, never a business value. `userName` unique globally would mean two
      // institutions could not both have an "admin".
      expect(field, `${plan.collection}.${plan.options.name}`).toMatch(/Id$|^kid$|^name$|^issuer$/);
    }
  });
});

describe('P11.12: no unbounded array, and every cap is asserted somewhere', () => {
  it('caps the embedded role array', () => {
    // The one array the ADR embeds against general advice. Bounded, and the bound is a number in
    // the model rather than a hope in a comment.
    expect(MAX_ROLE_HOLDINGS).toBeGreaterThan(0);
    expect(MAX_ROLE_HOLDINGS).toBeLessThanOrEqual(200);
  });

  it('caps the active client secrets, so a rotation window cannot grow', () => {
    expect(MAX_ACTIVE_CLIENT_SECRETS).toBe(2);
  });

  it('declares no TTL index on a collection whose expiring data is inside an array', () => {
    /**
     * The trap this catches cost a real defect during P2.
     *
     * A TTL index expires whole DOCUMENTS and never array elements. `principal.roles[]` carries an
     * `expiresAt` per entry, so a TTL on the principal would delete THE SUBJECT rather than the
     * lapsed role. Read-time filtering is the correctness mechanism; the sweeper is hygiene.
     */
    const principalTtl = plannedIndexes().filter(
      (plan) => plan.collection === 'principal' && plan.options.expireAfterSeconds !== undefined,
    );
    expect(principalTtl, 'a TTL on principal expires the subject, not the role').toEqual([]);
  });

  it('declares a TTL for every collection the registry marks ephemeral, and only those', () => {
    const marked = GIAM_COLLECTIONS.filter((spec) => spec.ttlField).map((spec) => spec.name).sort();
    const withTtl = [...new Set(
      plannedIndexes()
        .filter((plan) => plan.options.expireAfterSeconds !== undefined)
        .map((plan) => plan.collection),
    )].sort();
    expect(withTtl).toEqual(marked);
  });
});

describe('P11.12: no $lookup or $graphLookup on the token issuance path', () => {
  it('keeps the issuer free of any aggregation traversal', () => {
    /**
     * Issuing a token must be one read plus one write, and a traversal is neither.
     *
     * Role composition IS resolved with a `$graphLookup`, and that is allowed: it happens at the
     * DECISION point, when a resource server asks what a role expands to, not when a token is
     * minted. A token carries roles by default precisely so issuance never has to expand them.
     */
    const issuer = sourceFiles().find((file) => file.path === 'modules/oauth/services/tokenIssuer.service.ts');
    expect(issuer, 'the issuer moved and this test did not follow').toBeTruthy();
    expect(issuer!.text).not.toMatch(/\$graphLookup/);
    expect(issuer!.text).not.toMatch(/\$lookup/);
  });

  it('bounds the traversal that does exist, so a cycle cannot become unbounded', () => {
    const withTraversal = sourceFiles().filter((file) => file.text.includes('$graphLookup'));
    expect(withTraversal.length, 'no traversal found; has role composition moved?').toBeGreaterThan(0);
    for (const file of withTraversal) {
      expect(file.text, `${file.path} traverses without a depth bound`).toMatch(/maxDepth/);
    }
  });
});

describe('P11.12: nothing redeemable is stored at rest', () => {
  it('holds no token collection, and no collection named for one', () => {
    // The highest write rate in the system, on data carrying nothing the token did not already
    // carry, plus a redeemable artifact at rest. All three reasons it is gone.
    const names = GIAM_COLLECTIONS.map((spec) => spec.name);
    expect(names).not.toContain('token');
    expect(names).not.toContain('refreshToken');
  });

  it('encrypts personal data and never a one-way hash', () => {
    // Encrypting a hash buys nothing and would put ESC/ECOC state on the credential collection,
    // which is now one of the hottest lookups in the system.
    const encrypted = GIAM_COLLECTIONS.filter((spec) => spec.encrypted).map((spec) => spec.name);
    expect(encrypted).toEqual(['principal']);
  });
});
