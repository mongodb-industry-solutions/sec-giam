/**
 * A reseed recomposes every persisted realm's issuer, not only the fixture-backed ones.
 *
 * A realm created at runtime kept the issuer it was stored with, so after the address scheme moved
 * under `/api/v1` its discovery and tokens named routes that no longer exist.
 */
import { describe, it, expect } from 'vitest';
import type { Collection } from 'mongodb';
import { recomposeIssuers } from '../../../backend/src/vendors/seed/seedRealms';
import { realmIssuer } from '../../../backend/src/config';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';

function fakeRealms(records: Array<Partial<RealmRecord>>) {
  const writes: Array<{ realmId: string; issuer: string }> = [];
  const collection = {
    find: () => ({ toArray: async () => records }),
    updateOne: async (filter: { realmId: string }, update: { $set: { issuer: string } }) => {
      writes.push({ realmId: filter.realmId, issuer: update.$set.issuer });
      return { modifiedCount: 1 };
    },
  } as unknown as Collection<RealmRecord>;
  return { collection, writes };
}

describe('reseed recomposes stored issuers', () => {
  it('rewrites a runtime-created realm still carrying the pre-/api/v1 issuer', async () => {
    const { collection, writes } = fakeRealms([
      { realmId: 'r-1', name: 'custom', issuer: 'http://127.0.0.1:8085/realms/custom', meta: newMeta('Realm') },
    ]);
    await recomposeIssuers(collection);
    expect(writes).toEqual([{ realmId: 'r-1', issuer: realmIssuer('custom') }]);
    expect(realmIssuer('custom')).toContain('/api/v1/realms/custom');
  });

  it('leaves a realm whose issuer is already current untouched', async () => {
    const { collection, writes } = fakeRealms([
      { realmId: 'r-2', name: 'current', issuer: realmIssuer('current'), meta: newMeta('Realm') },
    ]);
    await recomposeIssuers(collection);
    expect(writes).toEqual([]);
  });
});
