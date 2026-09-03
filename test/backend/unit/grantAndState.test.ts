// v40 P7: a delegation is a grant with a purpose, and a flow is discarded while a fact is kept.
//
// Two claims, and the second is the one that would fail silently. Merging delegation into grant is
// visible the moment anything reads the wrong field. But "failed attempt analysis belongs in audit,
// never in state" only fails at the TTL boundary, minutes later, when the record that was
// answering the question quietly stops existing. So that boundary is asserted directly.
import { describe, it, expect } from 'vitest';
import {
  covers, isDelegation, isExercisable, narrowScope, grantedScopes, chainDepth,
} from '../../../backend/src/modules/consent/models/grant.model';
import type { GrantRecord } from '../../../backend/src/modules/consent/models/grant.model';
import { isRedeemable } from '../../../backend/src/modules/oauth/models/state.model';
import type { StateRecord, AuthorizationFlow } from '../../../backend/src/modules/oauth/models/state.model';
import { GIAM_COLLECTIONS } from '../../../backend/src/shared/models/collections';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';

const CONSENT: GrantRecord = {
  realmId: 'r1',
  tenantId: 'default',
  grantId: 'g-1',
  subjectId: 'sub-1',
  clientId: 'app-1',
  scope: 'openid profile',
  status: 'active',
  grantedAt: '2026-01-01T00:00:00.000Z',
  meta: { resourceType: 'Grant', created: '2026-01-01T00:00:00.000Z', lastModified: '2026-01-01T00:00:00.000Z', version: 'W/"1"' },
};

const DELEGATION: GrantRecord = {
  ...CONSENT,
  grantId: 'g-2',
  agentSubjectId: 'agent-1',
  purpose: 'reconcile the disputed transaction the account holder reported',
  scope: 'payments:read payments:refund',
  maxDepth: 0,
  expiresAt: '2099-01-01T00:00:00.000Z',
  constraints: { maxValue: 500 },
};

describe('P7: one collection, and purpose is what tells the two apart', () => {
  it('holds no delegation collection any more', () => {
    // The merge, asserted where it cannot drift: the registry.
    expect(GIAM_COLLECTIONS.map((spec) => spec.name)).not.toContain('delegation');
    expect(GIAM_COLLECTIONS.map((spec) => spec.name)).toContain('grant');
  });

  it('reads a purpose as the discriminator, and its absence as an ordinary consent', () => {
    expect(isDelegation(DELEGATION)).toBe(true);
    expect(isDelegation(CONSENT)).toBe(false);
    // An empty purpose is not a purpose. Otherwise a delegation could be created that recorded no
    // reason, which is the one thing a purpose exists to prevent.
    expect(isDelegation({ purpose: '' })).toBe(false);
  });

  it('carries the constraints a scope cannot express', () => {
    // A delegation to move money is not the same as one to move money up to a limit, and these are
    // checked by the application that knows what a value means.
    expect(DELEGATION.constraints?.maxValue).toBe(500);
    expect(CONSENT.constraints).toBeUndefined();
  });
});

describe('P7: every exercisability clause fails closed', () => {
  it('grants nothing once revoked or expired', () => {
    expect(isExercisable(DELEGATION)).toBe(true);
    expect(isExercisable({ ...DELEGATION, status: 'revoked' })).toBe(false);
    expect(isExercisable({ ...DELEGATION, status: 'expired' })).toBe(false);
    expect(isExercisable({ ...DELEGATION, expiresAt: '2020-01-01T00:00:00.000Z' })).toBe(false);
  });

  it('grants nothing before it has started', () => {
    const later = new Date(Date.now() + 3600_000).toISOString();
    expect(isExercisable({ ...DELEGATION, notBefore: later })).toBe(false);
  });

  it('lets an ordinary consent stand with no expiry, which a delegation should not', () => {
    // A consent legitimately stands until withdrawn; a delegation with no end is one nobody
    // revisits. The model allows both and the difference is a seeding decision, not a type error.
    expect(isExercisable(CONSENT)).toBe(true);
    expect(CONSENT.expiresAt).toBeUndefined();
  });

  it('covers a request only when it covers ALL of it', () => {
    expect(covers(CONSENT, ['openid'])).toBe(true);
    expect(covers(CONSENT, ['openid', 'profile'])).toBe(true);
    // A partial grant is not a grant.
    expect(covers(CONSENT, ['openid', 'payments:read'])).toBe(false);
    expect(covers({ ...CONSENT, status: 'revoked' }, ['openid'])).toBe(false);
  });
});

describe('P7: a delegated hop may only narrow', () => {
  it('intersects rather than unions, so a chain cannot widen', () => {
    expect(narrowScope(grantedScopes(DELEGATION), ['payments:read'])).toEqual(['payments:read']);
    // Asking for something the delegation never held does not add it.
    expect(narrowScope(grantedScopes(DELEGATION), ['payments:write'])).toEqual(grantedScopes(DELEGATION));
  });

  it('counts the chain, because an unbounded one is untraceable', () => {
    expect(chainDepth(undefined)).toBe(0);
    expect(chainDepth({ actor: { actor: undefined } })).toBe(2);
  });
});

describe('P7: a flow is transient, and the fact outlives it', () => {
  const pending: Pick<StateRecord, 'status' | 'expiresAt'> = {
    status: 'pending',
    expiresAt: new Date(Date.now() + 120_000).toISOString(),
  };

  it('marks a redeemed code consumed rather than deleting it', () => {
    // P7.3. A replay has to be DETECTED, not merely absent: deleting on use makes a replayed code
    // and a fabricated one indistinguishable, and one is a typo while the other is an attack.
    expect(isRedeemable(pending)).toBe(true);
    expect(isRedeemable({ ...pending, status: 'consumed' })).toBe(false);
    expect(isRedeemable({ ...pending, expiresAt: '2020-01-01T00:00:00.000Z' })).toBe(false);
  });

  it('keeps the state TTL bounded, which is what makes it unfit for analysis', () => {
    // The reason failed-attempt analysis cannot live here: the record is gone in minutes. A TTL
    // index on the collection is the mechanism, so its presence is the assertion.
    const spec = GIAM_COLLECTIONS.find((entry) => entry.name === 'state');
    expect(spec?.ttlField).toBe('expiresAt');
    const ttl = plannedIndexes().find(
      (plan) => plan.collection === 'state' && plan.options.expireAfterSeconds !== undefined,
    );
    expect(ttl).toBeTruthy();
    expect(ttl?.options.expireAfterSeconds).toBe(0);
  });

  it('keeps audit as a long-retention time series, so the fact survives the flow', () => {
    /**
     * The other half of the same claim, and the reason P7.6 exists.
     *
     * A failed sign-in must still be answerable after the state record that carried it has expired.
     * That only holds if audit is a separate, long-retention collection with NO TTL, so the two
     * properties are asserted together: the flow expires, the evidence does not.
     */
    const audit = GIAM_COLLECTIONS.find((entry) => entry.name === 'audit');
    expect(audit?.kind).toBe('timeseries');
    expect(audit?.ttlField).toBeUndefined();

    const auditTtl = plannedIndexes().filter(
      (plan) => plan.collection === 'audit' && plan.options.expireAfterSeconds !== undefined,
    );
    expect(auditTtl, 'a TTL on audit would discard the evidence the flow was discarded for').toEqual([]);
  });

  it('reserves par as a third flow rather than a fourth collection', () => {
    // P7.4. When Pushed Authorization Requests arrive they are another way of starting the same
    // thing, so they are a value here and not a collection with its own TTL and its own expiry bug.
    const flows: AuthorizationFlow[] = ['authorization_code', 'ciba', 'par'];
    expect(flows).toContain('par');
  });
});
