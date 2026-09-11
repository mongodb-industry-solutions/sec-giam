// The client fixtures are the source of truth for what applications exist, so the file itself has
// to be free of the duplicate the seeder would faithfully reproduce.
//
// This is not the seeder's idempotency, which `setupIdempotency.test.ts` covers: the seeder upserts
// on `{realmId, clientId, type}` and is correct. It is the input. Two fixtures naming the SAME
// application under two client ids seed two registrations, and the applications list then shows one
// application twice. Nothing downstream can tell those apart from two genuinely different
// applications, which is why it has to be caught here, in the data.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

interface ClientFixture {
  realm: string;
  clientId: string;
  clientName: string;
}

const fixtures = JSON.parse(
  readFileSync(resolve(__dirname, '../../../backend/data/clients.json'), 'utf8'),
) as ClientFixture[];

function duplicatesBy(key: (fixture: ClientFixture) => string): string[] {
  const seen = new Map<string, number>();
  for (const fixture of fixtures) seen.set(key(fixture), (seen.get(key(fixture)) ?? 0) + 1);
  return [...seen.entries()].filter(([, count]) => count > 1).map(([value]) => value);
}

describe('the client fixtures describe each application exactly once', () => {
  it('is a non-empty list, so the assertions below have something to check', () => {
    expect(fixtures.length).toBeGreaterThan(0);
  });

  /** The upsert key. Two fixtures sharing it would make the later one silently overwrite the earlier. */
  it('names each client id once per realm', () => {
    expect(duplicatesBy((f) => `${f.realm}|${f.clientId}`)).toEqual([]);
  });

  /**
   * The display name, which is what a person reads in the applications list.
   *
   * Two registrations of one application is a legitimate thing to WANT (a separate credential per
   * environment, say), but then they are not the same application to anybody administering them and
   * must not read as one name twice. If a deployment genuinely needs two, they get names that say
   * which is which, and this assertion is what forces that decision to be made deliberately.
   */
  it('names each application once per realm', () => {
    expect(duplicatesBy((f) => `${f.realm}|${f.clientName}`)).toEqual([]);
  });

});
