// Setup and seed have to CONVERGE an existing database, not only add to it.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  classifyIndex, reconcileIndexes, reconcilable, plannedIndexes, ExistingIndex,
} from '../../../backend/src/vendors/setup/createIndexes';
import { verdictOf, ValidationCheck } from '../../../backend/src/vendors/setup/validateSetup';
import {
  collectionsWithRetiredFields, CLIENT_COLLECTION, CREDENTIAL_COLLECTION, AUDIT_COLLECTION,
} from '../../../backend/src/shared/models/collections';
import { RETIRED_CLIENT_FIELDS } from '../../../backend/src/modules/oauth/models/client.model';
import { retireDeclaredFields } from '../../../backend/src/vendors/seed/upsertSeed';

// A Db stub with only what these two functions reach for.
interface FakeCollection {
  indexes: ExistingIndex[];
  documents: Array<Record<string, unknown>>;
  dropped: string[];
  unset: Array<Record<string, unknown>>;
}

function fakeDb(collections: Record<string, Partial<FakeCollection>>) {
  const state: Record<string, FakeCollection> = {};
  for (const [name, value] of Object.entries(collections)) {
    state[name] = {
      indexes: value.indexes ?? [],
      documents: value.documents ?? [],
      dropped: [],
      unset: [],
    };
  }
  const db = {
    listCollections: () => ({ toArray: async () => Object.keys(state).map((name) => ({ name })) }),
    collection: (name: string) => ({
      indexes: async () => state[name]?.indexes ?? [],
      dropIndex: async (indexName: string) => { state[name].dropped.push(indexName); },
      countDocuments: async (filter: { $or: Array<Record<string, unknown>> }) =>
        state[name].documents.filter((doc) => filter.$or.some((clause) => Object.keys(clause)[0] in doc)).length,
      updateMany: async (_filter: unknown, update: { $unset: Record<string, unknown> }) => {
        state[name].unset.push(update.$unset);
        for (const doc of state[name].documents) {
          for (const field of Object.keys(update.$unset)) delete doc[field];
        }
      },
    }),
  };
  return { db, state };
}

const CLIENT_PLAN = new Set(
  plannedIndexes().filter((plan) => plan.collection === CLIENT_COLLECTION).map((plan) => plan.options.name),
);

describe('index reconciliation', () => {
  beforeEach(() => { vi.spyOn(console, 'log').mockImplementation(() => {}); });
  afterEach(() => { vi.restoreAllMocks(); });

  it('calls an index the plan no longer declares obsolete', () => {
    // The real case: the owner index was renamed when its keys changed, since reusing a name with
    // different keys errors on a database that was never reset.
    const stale: ExistingIndex = { name: 'realm_owner', key: { realmId: 1, 'owner.kind': 1 } };
    expect(classifyIndex(stale, CLIENT_PLAN, true)).toBe('obsolete');
  });

  it('calls a declared index and _id_ planned', () => {
    expect(classifyIndex({ name: 'realm_owners', key: { realmId: 1 } }, CLIENT_PLAN, true)).toBe('planned');
    expect(classifyIndex({ name: '_id_', key: { _id: 1 } }, CLIENT_PLAN, true)).toBe('planned');
  });

  it('refuses to judge an index it did not declare', () => {
    const safeContent: ExistingIndex = { name: '__safe_content__', key: { __safeContent__: 1 } };
    expect(classifyIndex(safeContent, CLIENT_PLAN, true)).toBe('engine');
    expect(classifyIndex({ name: 'text', key: { a: 'text' }, weights: { a: 1 } }, CLIENT_PLAN, true)).toBe('unrecognised');
    // A collection with no declared index is not under plan management at all.
    expect(classifyIndex({ name: 'whatever', key: { a: 1 } }, new Set(), false)).toBe('unrecognised');
  });

  it('drops the obsolete index and leaves the unrecognised one in place', async () => {
    const { db, state } = fakeDb({
      [CLIENT_COLLECTION]: {
        indexes: [
          { name: '_id_', key: { _id: 1 } },
          { name: 'realm_owners', key: { realmId: 1, 'owners.kind': 1, 'owners.ref': 1 } },
          { name: 'realm_owner', key: { realmId: 1, 'owner.kind': 1 } },
          { name: '__safe_content__', key: { __safeContent__: 1 } },
        ],
      },
    });
    await reconcileIndexes(db as never);
    expect(state[CLIENT_COLLECTION].dropped).toEqual(['realm_owner']);
  });

  it('leaves a time series alone, since its default meta index belongs to the engine', async () => {
    const { db, state } = fakeDb({
      [AUDIT_COLLECTION]: { indexes: [{ name: 'meta_1_ts_1', key: { meta: 1, ts: 1 } }] },
    });
    expect(reconcilable(AUDIT_COLLECTION)).toBe(false);
    await reconcileIndexes(db as never);
    expect(state[AUDIT_COLLECTION].dropped).toEqual([]);
  });

  it('never drops a collection or a document', async () => {
    const { db, state } = fakeDb({
      [CLIENT_COLLECTION]: {
        indexes: [{ name: 'realm_owner', key: { realmId: 1, 'owner.kind': 1 } }],
        documents: [{ clientId: 'a' }],
      },
    });
    await reconcileIndexes(db as never);
    expect(Object.keys(state)).toEqual([CLIENT_COLLECTION]);
    expect(state[CLIENT_COLLECTION].documents).toHaveLength(1);
  });
});

describe('retired fields', () => {
  beforeEach(() => { vi.spyOn(console, 'log').mockImplementation(() => {}); });
  afterEach(() => { vi.restoreAllMocks(); });

  it('declares the retired field next to the model that retired it', () => {
    // v40: the OAuth client registration is a credential of type oauth_client, so the fields its
    // model retired are declared on the collection that now carries the record.
    expect(RETIRED_CLIENT_FIELDS).toContain('owner');
    const spec = collectionsWithRetiredFields().find((s) => s.name === CREDENTIAL_COLLECTION);
    expect(spec?.retiredFields).toContain('owner');
  });

  it('never retires a field the model still declares', () => {
    // The registry is only safe if nothing declared retired is also written. `owners` is the live one.
    for (const spec of collectionsWithRetiredFields()) {
      expect(spec.retiredFields).not.toContain('owners');
    }
  });

  it('unsets a retired field wherever it survives, and touches nothing else', async () => {
    const { db, state } = fakeDb({
      [CREDENTIAL_COLLECTION]: {
        documents: [
          { clientId: 'a', owner: { kind: 'principal' }, owners: [{ kind: 'principal' }] },
          { clientId: 'b', owners: [{ kind: 'principal' }] },
        ],
      },
    });
    await retireDeclaredFields(db as never);
    expect(state[CREDENTIAL_COLLECTION].unset).toEqual([{ owner: '' }]);
    expect(state[CREDENTIAL_COLLECTION].documents).toEqual([
      { clientId: 'a', owners: [{ kind: 'principal' }] },
      { clientId: 'b', owners: [{ kind: 'principal' }] },
    ]);
  });

  it('writes nothing when no retired field survives', async () => {
    const { db, state } = fakeDb({ [CREDENTIAL_COLLECTION]: { documents: [{ clientId: 'a' }] } });
    await retireDeclaredFields(db as never);
    expect(state[CREDENTIAL_COLLECTION].unset).toEqual([]);
  });
});

describe('the validation verdict', () => {
  const check = (ok: boolean, severity: ValidationCheck['severity']): ValidationCheck =>
    ({ name: 'n', ok, severity });

  it('is converged when everything passes', () => {
    expect(verdictOf([check(true, 'error'), check(true, 'warning')])).toBe('converged');
  });

  it('is converged with warnings when only warnings fail', () => {
    expect(verdictOf([check(true, 'error'), check(false, 'warning')])).toBe('converged-with-warnings');
  });

  it('is not converged when something declared is missing', () => {
    expect(verdictOf([check(false, 'error'), check(false, 'warning')])).toBe('not-converged');
  });

  it('requires a reset whenever one check says so, whatever else failed', () => {
    expect(verdictOf([check(false, 'error'), check(false, 'reset')])).toBe('requires-reset');
  });
});
