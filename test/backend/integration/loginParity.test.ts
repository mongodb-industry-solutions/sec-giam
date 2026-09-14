// v39 P9.9: the sign-in screen moved, and the demonstration must not have got worse.
//
// The security argument for moving login to the authority is easy. The risk is that the move quietly
// costs the affordances a booth demonstration actually runs on: the branding that makes the page look
// like the relying party's, the roster of personas, and one ready-made user per role so a presenter
// can switch persona in one click rather than typing credentials.
//
// Those are not decoration. A presenter who has to remember which of 68 seeded people is an
// investigator will stop demonstrating the investigator flow. So this asserts the affordances persona
// by persona rather than trusting that the page looks right.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const DATA = resolve(__dirname, '../../../backend/data');

interface IdentityFixture {
  realm: string;
  subjectId: string;
  userName: string;
  email?: string;
  demoFeatured?: boolean;
  roleName?: string;
  lifecycleState?: string;
}

/**
 * BOTH fixtures, because the realm holds both populations now (ADR-003).
 *
 * The bank's people are declared in their own file and live in the shared realm. Reading only one
 * file made the roster look as though it named ten personas nobody had declared, when in fact the
 * declaration was simply in the file this test was not reading.
 */
const identities = [
  ...JSON.parse(readFileSync(resolve(DATA, 'identities.json'), 'utf8')) as IdentityFixture[],
  ...JSON.parse(readFileSync(resolve(DATA, 'bankIdentities.json'), 'utf8')) as IdentityFixture[],
];
const realms = JSON.parse(readFileSync(resolve(DATA, 'realms.json'), 'utf8')) as Array<{
  name: string;
  displayName: string;
  branding?: { displayName?: string; primaryColor?: string };
  domains: Array<{ name: string; protocol: string; enabled?: boolean; notice?: string }>;
}>;

const REALM = realms[0].name;

interface LoginContext {
  realm: string;
  displayName: string;
  branding: { displayName?: string; primaryColor?: string };
  providers: Array<{ name: string; displayName: string; protocol: string; enabled: boolean; notice?: string }>;
  roster: Array<{ subjectId: string; userName: string; email?: string; role?: string }>;
  registrationEnabled: boolean;
}

let app: FastifyInstance;
let context: LoginContext;

beforeAll(async () => {
  const { buildApp } = await import('../../../backend/src/app');
  app = await buildApp();
  await app.ready();

  const response = await app.inject({ method: 'GET', url: `/realms/${REALM}/login-context` });
  expect(response.statusCode, 'the sign-in screen must be able to render at all').toBe(200);
  context = response.json() as LoginContext;
}, 120_000);

afterAll(async () => {
  await app?.close();
});

describe('v39 P9.9: the sign-in screen carries the relying party, not the authority', () => {
  it('renders the realm branding rather than this console name', () => {
    // The point of theming: a person sees the page of the product they are signing in to. An
    // authority that imposes its own branding makes every relying party look like it was acquired.
    expect(context.branding).toBeTruthy();
    expect(context.branding.displayName ?? context.displayName).toBeTruthy();
  });

  it('offers every way in, the realm own directory included', () => {
    /**
     * v40 P8.5 changed what this list means, deliberately.
     *
     * The sign-in screen is a projection of the realm DOMAIN list, and the realm's own directory is
     * one domain among the others rather than a special case sitting outside the list. The fixture
     * now declares it in that same list, so the count is simply the list's length: there is no
     * "plus one" because there is nothing the seeder adds that the fixture did not ask for.
     *
     * That is the whole point of the widening: a realm with three ways in offers three, and adding
     * a fourth is data rather than a branch in the page.
     */
    expect(context.providers.length).toBe(realms[0].domains.length);
    const local = context.providers.filter((entry) => entry.protocol === 'internal');
    expect(local, 'the realm own directory is not offered as a way in').toHaveLength(1);
  });

  it('says so when a provider is visible but not usable', () => {
    // Better than hiding it or failing after it is chosen: somebody looking for their employer's
    // sign-in learns where it stands instead of concluding the product cannot do it.
    for (const provider of context.providers.filter((entry) => !entry.enabled)) {
      expect(provider.notice, `${provider.name} is disabled with no explanation`).toBeTruthy();
    }
  });
});

describe('v39 P9.9: the demo roster survived the move, persona by persona', () => {
  const featured = identities.filter(
    (identity) => identity.realm === REALM && identity.demoFeatured && identity.lifecycleState !== 'deprovisioned',
  );

  it('offers a roster at all', () => {
    expect(featured.length, 'the fixture declares no demo personas, so this test proves nothing').toBeGreaterThan(0);
    expect(context.roster.length).toBeGreaterThan(0);
  });

  it('offers every declared persona, and nobody who was not declared', () => {
    const offered = new Set(context.roster.map((entry) => entry.subjectId));
    const declared = new Set(featured.map((identity) => identity.subjectId));

    const missing = [...declared].filter((subjectId) => !offered.has(subjectId));
    expect(missing, `declared demo personas absent from the roster: ${missing.join(', ')}`).toEqual([]);

    // The other direction matters more: a roster naming somebody who is not a declared persona is a
    // disclosure of a real principal on an unauthenticated page.
    const extra = [...offered].filter((subjectId) => !declared.has(subjectId));
    expect(extra, `roster names principals not declared as demo personas: ${extra.join(', ')}`).toEqual([]);
  });

  it('gives a presenter one ready-made user for every role', () => {
    const rolesWithAPersona = new Set(
      context.roster.map((entry) => entry.role).filter(Boolean) as string[],
    );
    const rolesThatShouldHaveOne = new Set(
      featured.map((identity) => identity.roleName).filter(Boolean) as string[],
    );

    const unreachable = [...rolesThatShouldHaveOne].filter((role) => !rolesWithAPersona.has(role));
    // A role with no one-click persona is a flow that will not get demonstrated, because nobody
    // remembers which of 68 people holds it.
    expect(unreachable, `roles with no one-click persona: ${unreachable.join(', ')}`).toEqual([]);
  });

  it('carries what the button needs to sign in, for every persona', () => {
    for (const entry of context.roster) {
      expect(entry.userName, `${entry.subjectId} has no name to sign in with`).toBeTruthy();
      expect(entry.subjectId, 'a roster entry with no subject cannot be rendered stably').toBeTruthy();
    }
  });

  it('discloses nothing a sign-in page does not already show', () => {
    /**
     * The roster is on an UNAUTHENTICATED page, so this is the bound that keeps it acceptable.
     *
     * Never a credential, never a hash, never a business reference. `demoNote` is permitted and
     * belongs here: it is a deliberately OPAQUE hint written by whoever wrote the fixture, so a
     * demonstration can tell two personas holding the same role apart without this authority
     * learning what a merchant, an account or a case is. That opacity is the whole reason it is
     * safe on an unauthenticated page, and it is why widening the set here is a decision rather
     * than an accommodation.
     *
     * `displayName` was added by v41 P8 and DISCLOSES NOTHING NEW, which is the argument for it
     * rather than a plea. Until P8 the person's name was in `userName`, on this same page, because
     * a display name had been written into the login field. P8 separated the two, so the name now
     * appears under the field that means "name" and the login appears under the field that means
     * "login". The set of facts on the page is unchanged; only the naming was corrected.
     */
    const permitted = new Set(['subjectId', 'userName', 'displayName', 'email', 'role', 'demoNote']);
    for (const entry of context.roster) {
      const leaked = Object.keys(entry).filter((field) => !permitted.has(field));
      expect(leaked, `roster entry exposes ${leaked.join(', ')}`).toEqual([]);
    }
  });
});
