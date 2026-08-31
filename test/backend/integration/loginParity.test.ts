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

const DATA = resolve(__dirname, '../../../../giam/backend/data');

interface IdentityFixture {
  realm: string;
  subjectId: string;
  userName: string;
  email?: string;
  demoFeatured?: boolean;
  roleName?: string;
  lifecycleState?: string;
}

const identities = JSON.parse(readFileSync(resolve(DATA, 'identities.json'), 'utf8')) as IdentityFixture[];
const realms = JSON.parse(readFileSync(resolve(DATA, 'realms.json'), 'utf8')) as Array<{
  name: string;
  displayName: string;
  branding?: { displayName?: string; primaryColor?: string };
  providers?: Array<{ name: string; enabled: boolean; notice?: string }>;
}>;

const REALM = realms[0].name;

interface LoginContext {
  realm: string;
  displayName: string;
  branding: { displayName?: string; primaryColor?: string };
  providers: Array<{ name: string; displayName: string; enabled: boolean; notice?: string }>;
  roster: Array<{ subjectId: string; userName: string; email?: string; role?: string }>;
  registrationEnabled: boolean;
}

let app: FastifyInstance;
let context: LoginContext;

beforeAll(async () => {
  const { buildApp } = await import('../../../../giam/backend/src/app');
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

  it('offers the federated providers a person may choose', () => {
    const configured = realms[0].providers ?? [];
    expect(context.providers.length).toBe(configured.length);
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
    // The roster is on an unauthenticated page, so this is the bound that keeps it acceptable: a
    // name, optionally an email, and the role. Never a credential, a hash, or a business reference.
    const permitted = new Set(['subjectId', 'userName', 'email', 'role']);
    for (const entry of context.roster) {
      const leaked = Object.keys(entry).filter((field) => !permitted.has(field));
      expect(leaked, `roster entry exposes ${leaked.join(', ')}`).toEqual([]);
    }
  });
});
