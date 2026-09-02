// The validation has to tell the whole truth: what is missing, what is extra, and what no amount of
// re-running setup can fix.
import { describe, it, expect, vi } from 'vitest';

vi.mock('../../../backend/src/vendors/encryption/qeClient', () => ({
  assertCryptSharedLib: () => 'stub',
}));
vi.mock('../../../backend/src/vendors/encryption/keyVault', () => ({
  findOrphanedDeks: async () => [],
}));

import { validateSetup } from '../../../backend/src/vendors/setup/validateSetup';
import {
  CLIENT_COLLECTION, CREDENTIAL_COLLECTION, REALM_COLLECTION, PRINCIPAL_COLLECTION,
} from '../../../backend/src/shared/models/collections';

interface Fixture {
  options?: Record<string, unknown>;
  type?: string;
  indexes?: Array<Record<string, unknown>>;
  documents?: Array<Record<string, unknown>>;
}

function matches(doc: Record<string, unknown>, filter: Record<string, unknown>): boolean {
  const or = filter.$or as Array<Record<string, unknown>> | undefined;
  if (or) return or.some((clause) => matches(doc, clause));
  return Object.entries(filter).every(([key, condition]) => {
    if (condition && typeof condition === 'object' && '$exists' in (condition as object)) {
      return (key in doc) === (condition as { $exists: boolean }).$exists;
    }
    return doc[key] === condition;
  });
}

function fakeDb(fixtures: Record<string, Fixture>) {
  return {
    client: {},
    listCollections: () => ({
      toArray: async () => Object.entries(fixtures).map(([name, f]) => ({
        name, type: f.type ?? 'collection', options: f.options ?? {},
      })),
    }),
    collection: (name: string) => ({
      estimatedDocumentCount: async () => fixtures[name]?.documents?.length ?? 0,
      countDocuments: async (filter: Record<string, unknown> = {}) =>
        (fixtures[name]?.documents ?? []).filter((doc) => matches(doc, filter)).length,
      indexes: async () => fixtures[name]?.indexes ?? [],
      find: () => ({ toArray: async () => fixtures[name]?.documents ?? [] }),
    }),
  } as never;
}

async function run(fixtures: Record<string, Fixture>) {
  return validateSetup(fakeDb(fixtures));
}

const detailOf = (checks: Array<{ name: string; detail?: string }>, needle: string) =>
  checks.find((check) => check.name.includes(needle));

describe('validateSetup reports every condition', () => {
  it('names a collection the model declares and the database does not have', async () => {
    const { checks } = await run({});
    const realm = detailOf(checks, `collection ${REALM_COLLECTION}`);
    expect(realm?.ok).toBe(false);
    expect(realm?.detail).toBe('missing');
  });

  it('names a collection the database has and the model does not declare', async () => {
    const { checks } = await run({ leftovers: {} });
    const check = detailOf(checks, 'registered with an owning module');
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain('leftovers');
  });

  it('names an index that is present and no longer declared', async () => {
    const { checks } = await run({
      [CLIENT_COLLECTION]: {
        indexes: [
          { name: '_id_', key: { _id: 1 } },
          { name: 'realm_owner', key: { realmId: 1, 'owner.kind': 1 } },
        ],
      },
    });
    const check = detailOf(checks, `${CLIENT_COLLECTION} carries no index the model dropped`);
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain('realm_owner');
    expect(check?.severity).toBe('warning');
  });

  it('leaves an index it cannot judge alone, and says so', async () => {
    const { checks } = await run({
      [CLIENT_COLLECTION]: {
        indexes: [
          { name: '__safe_content__', key: { __safeContent__: 1 } },
          { name: 'hand_made', key: { $weird: 1 } },
        ],
      },
    });
    const check = detailOf(checks, 'nobody can account for');
    expect(check?.detail).toContain('hand_made');
    // The driver's own index is present by design, so it is not reported at all.
    expect(check?.detail).not.toContain('__safe_content__');
    const obsolete = detailOf(checks, 'carries no index the model dropped');
    expect(obsolete?.ok).toBe(true);
  });

  it('counts the documents that still hold a retired field', async () => {
    const { checks } = await run({
      [CREDENTIAL_COLLECTION]: { documents: [{ owner: {} }, { owners: [] }] },
    });
    const check = detailOf(checks, 'holds no field the model retired');
    expect(check?.ok).toBe(false);
    expect(check?.detail).toContain('1 document(s) still hold owner');
  });

  it('says plainly that encrypted-field drift needs a rebuild and cannot be set up away', async () => {
    const { checks, verdict, resetReasons } = await run({
      [PRINCIPAL_COLLECTION]: { options: { encryptedFields: { fields: [] } } },
    });
    const check = detailOf(checks, `encrypted fields on ${PRINCIPAL_COLLECTION}`);
    expect(check?.ok).toBe(false);
    expect(check?.severity).toBe('reset');
    expect(check?.detail).toContain('setup:db:reset');
    expect(check?.detail).toContain('never fix this');
    expect(verdict).toBe('requires-reset');
    expect(resetReasons.join(' ')).toContain(PRINCIPAL_COLLECTION);
  });
});
