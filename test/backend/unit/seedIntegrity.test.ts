// v41 P8: a login is an identifier, and a name is a name.
//
// All 70 seeded principals held a display name in `userName` ("Luis Fernandez", "Mr. Loren Raynor"),
// duplicating `name.formatted` exactly. That field is the `findByLogin` lookup, the SCIM filter
// target, and carries a unique index, so the values were unusable logins, and the API's own examples
// (`userName: "ada"`) disagreed with the data shipped beside them.
//
// A generator can regress this in one commit, so it is asserted rather than reviewed.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

interface Fixture {
  realm: string;
  subjectId: string;
  userName: string;
  email?: string;
  name?: {
    formatted?: string;
    givenName?: string;
    familyName?: string;
    honorificPrefix?: string;
    honorificSuffix?: string;
  };
}

const FIXTURES = ['identities.json', 'bankIdentities.json'];

function load(file: string): Fixture[] {
  return JSON.parse(readFileSync(resolve(__dirname, '../../../backend/data', file), 'utf8')) as Fixture[];
}

/** Titles and suffixes, which the standard gives their own attributes and which are not given names. */
const TITLES = /^(mr|mrs|ms|miss|dr|prof|sir|dame|mx)\.?$/i;
const SUFFIXES = /^(i|ii|iii|iv|v|jr|sr|phd|md|dds|dvm)\.?$/i;

describe.each(FIXTURES)('%s: userName is a login identifier', (file) => {
  const fixtures = load(file);

  it('is present on every principal', () => {
    expect(fixtures.length).toBeGreaterThan(0);
    for (const fixture of fixtures) {
      expect(fixture.userName, fixture.subjectId).toBeTruthy();
    }
  });

  it('contains no whitespace, because it is typed into a login field', () => {
    for (const fixture of fixtures) {
      expect(fixture.userName, fixture.userName).not.toMatch(/\s/);
    }
  });

  it('is unique within its realm, since the collection carries a unique index on it', () => {
    const perRealm = new Map<string, Set<string>>();
    for (const fixture of fixtures) {
      const held = perRealm.get(fixture.realm) ?? new Set<string>();
      expect(held.has(fixture.userName), `duplicate login ${fixture.userName} in ${fixture.realm}`).toBe(false);
      held.add(fixture.userName);
      perRealm.set(fixture.realm, held);
    }
  });

  /**
   * The defect itself. Equal values mean somebody put the display name back in the login field, and
   * every other assertion here would still pass.
   */
  it('is never the display name over again', () => {
    for (const fixture of fixtures) {
      if (!fixture.name?.formatted) continue;
      expect(fixture.userName, fixture.subjectId).not.toBe(fixture.name.formatted);
    }
  });

  it('carries no title, which is not part of a login', () => {
    for (const fixture of fixtures) {
      expect(fixture.userName.toLowerCase(), fixture.userName).not.toMatch(/^(mr|mrs|ms|miss|dr|prof)\./);
    }
  });
});

describe.each(FIXTURES)('%s: the name parts are the right parts', (file) => {
  const fixtures = load(file);

  /**
   * A generator had been writing `{ givenName: "Mr.", familyName: "Loren Raynor" }`, so any surface
   * greeting somebody by their given name greeted them as "Mr.".
   */
  it('never puts a title or a suffix in givenName or familyName', () => {
    for (const fixture of fixtures) {
      const given = fixture.name?.givenName ?? '';
      const family = fixture.name?.familyName ?? '';
      expect(TITLES.test(given), `${fixture.userName} givenName=${given}`).toBe(false);
      expect(SUFFIXES.test(given), `${fixture.userName} givenName=${given}`).toBe(false);
      expect(TITLES.test(family), `${fixture.userName} familyName=${family}`).toBe(false);
      expect(SUFFIXES.test(family), `${fixture.userName} familyName=${family}`).toBe(false);
    }
  });

  it('keeps the title in its own SCIM attribute where there is one', () => {
    const titled = fixtures.filter((fixture) => TITLES.test((fixture.name?.formatted ?? '').split(' ')[0] ?? ''));
    for (const fixture of titled) {
      expect(fixture.name?.honorificPrefix, fixture.userName).toBeTruthy();
    }
  });

  it('gives every principal a display name to show', () => {
    for (const fixture of fixtures) {
      expect(fixture.name?.formatted, fixture.subjectId).toBeTruthy();
    }
  });
});

describe('clients.json: a machine identity is named the same way a person is', () => {
  interface ClientFixture {
    clientId: string;
    serviceIdentity?: { displayName?: string; userName?: string };
  }
  const clients = JSON.parse(
    readFileSync(resolve(__dirname, '../../../backend/data/clients.json'), 'utf8'),
  ) as ClientFixture[];

  /**
   * The same defect, in the fixture nobody looked at. Six service principals held strings like
   * "LeafyPay, as a registered third party" in `userName`, the field carrying the unique login
   * index. A machine's identifier is the client id it authenticates as, which is already its
   * subject; the sentence is a display name.
   */
  it('carries no login in the fixture at all, because the client id is the login', () => {
    const offenders = clients
      .filter((client) => client.serviceIdentity && 'userName' in client.serviceIdentity)
      .map((client) => client.clientId);
    expect(offenders, `serviceIdentity.userName survives on: ${offenders.join(', ')}`).toEqual([]);
  });

  it('gives every service principal a display name', () => {
    for (const client of clients) {
      if (!client.serviceIdentity) continue;
      expect(client.serviceIdentity.displayName, client.clientId).toBeTruthy();
    }
  });
});

describe('the identities that other records already name are preserved', () => {
  /**
   * `subjectId` values are written into audit rows, sessions and application records, so
   * regenerating them would break no test here and quietly orphan everything naming one. Asserting
   * the shape is the closest a unit test gets to asserting they were not touched.
   */
  it('keeps every subjectId a stable opaque identifier, and never a login or a name', () => {
    /**
     * Not asserted as a uuid: the bank fixtures use readable deterministic ids
     * (`bank-emp-0001-operations`) and that is a legitimate choice for seed data whose whole point is
     * to be recognisable in a demonstration. What matters is that it is opaque, stable and NOT the
     * login, because the two are separate identifiers and conflating them is how a rename to one
     * silently moves the other.
     */
    for (const file of FIXTURES) {
      for (const fixture of load(file)) {
        expect(fixture.subjectId, fixture.userName).toMatch(/^[A-Za-z0-9._:-]+$/);
        expect(fixture.subjectId.length, fixture.userName).toBeGreaterThan(7);
        expect(fixture.subjectId, fixture.userName).not.toBe(fixture.userName);
        expect(fixture.subjectId, fixture.userName).not.toBe(fixture.name?.formatted);
      }
    }
  });
});
