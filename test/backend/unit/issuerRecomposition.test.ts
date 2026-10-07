/**
 * The issuer is composed at runtime and never stored.
 *
 * The database is shared between deployments (local, staging, production), each with its own public
 * origin. A stored issuer would pin every one of them to whichever deployment seeded last.
 */
import { describe, it, expect } from 'vitest';
import type { Collection } from 'mongodb';
import { retireStoredIssuers } from '../../../backend/src/vendors/seed/seedRealms';
import { realmIssuer, realmNameFromIssuer } from '../../../backend/src/config';
import { withIssuer, StoredRealm } from '../../../backend/src/modules/realm/services/realm.service';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';

describe('issuer composition', () => {
  it('derives the issuer from the realm name when a record is read', () => {
    const stored = { realmId: 'r-1', name: 'custom' } as StoredRealm;
    expect(withIssuer(stored).issuer).toBe(realmIssuer('custom'));
    expect(withIssuer(stored).issuer).toContain('/api/v1/realms/custom');
  });

  it('resolves the realm name from an issuer of this deployment and from no other', () => {
    expect(realmNameFromIssuer(realmIssuer('acme'))).toBe('acme');
    expect(realmNameFromIssuer('http://elsewhere.example/api/v1/realms/acme')).toBeNull();
    expect(realmNameFromIssuer(`${realmIssuer('acme')}/extra`)).toBeNull();
  });
});

describe('seed removes the issuer an earlier release stored', () => {
  it('unsets the field on every realm that carries it', async () => {
    const calls: Array<{ filter: unknown; update: unknown }> = [];
    const collection = {
      updateMany: async (filter: unknown, update: unknown) => {
        calls.push({ filter, update });
        return { modifiedCount: 2 };
      },
    } as unknown as Collection<RealmRecord>;

    expect(await retireStoredIssuers(collection)).toBe(2);
    expect(calls).toEqual([{ filter: { issuer: { $exists: true } }, update: { $unset: { issuer: '' } } }]);
  });
});
