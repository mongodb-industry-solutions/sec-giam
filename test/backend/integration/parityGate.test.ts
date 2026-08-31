// v39 P5.8: the parity gate.
//
// The blocking question of the whole extraction: does every principal who can sign in today still
// sign in afterwards, with the SAME credential? Everything else in this plan can be corrected by a
// later commit. Discovering at the end that the demo population has to choose new passwords cannot.
//
// So this suite signs in as every seeded principal, against the real database, with the credential
// the platform seeded, and asserts the population is complete rather than merely non-empty. A gate
// that passes because it found nothing to check is the failure mode it exists to prevent.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import * as bcrypt from 'bcryptjs';

const DATA = resolve(__dirname, '../../../../giam/backend/data');

interface IdentityFixture {
  realm: string;
  subjectId: string;
  userName: string;
  email?: string;
  active: boolean;
  roleName?: string;
  demoFeatured?: boolean;
}

interface CredentialFixture {
  subjectId: string;
  type: string;
  secretHash?: string;
}

const identities = JSON.parse(readFileSync(resolve(DATA, 'identities.json'), 'utf8')) as IdentityFixture[];
const credentials = JSON.parse(readFileSync(resolve(DATA, 'credentials.json'), 'utf8')) as CredentialFixture[];

/**
 * The demo password, recovered from the seeded hashes rather than assumed.
 *
 * The platform seeds one shared password across the demo population. Finding it by verifying a
 * candidate against a real hash means this suite proves the HASHES work, not that a constant matches
 * another constant, which is the only version of this test worth running.
 */
const CANDIDATES = ['demo-password', 'Demo123!', 'demo1234', 'password'];

let app: FastifyInstance;
let demoPassword: string | null = null;
let realmName: string;

beforeAll(async () => {
  const { buildApp } = await import('../../../../giam/backend/src/app');
  app = await buildApp();
  await app.ready();

  realmName = identities[0].realm;

  const sample = credentials.find((credential) => credential.type === 'password' && credential.secretHash);
  for (const candidate of CANDIDATES) {
    if (sample?.secretHash && await bcrypt.compare(candidate, sample.secretHash)) {
      demoPassword = candidate;
      break;
    }
  }
}, 120_000);

afterAll(async () => {
  await app?.close();
});

async function signIn(login: string, password: string) {
  return app.inject({
    method: 'POST',
    url: `/realms/${realmName}/login`,
    payload: { login, password },
  });
}

describe('v39 P5.8: the population is what it was', () => {
  it('carries every principal the platform could sign in', () => {
    // Asserted exactly rather than "more than zero": a migration that silently dropped twelve people
    // would pass any looser check. 68 came across; the 69th was added afterwards so that every role
    // offers two demo personas, and a change to this number belongs in a diff.
    expect(identities).toHaveLength(69);
    expect(new Set(identities.map((identity) => identity.subjectId)).size).toBe(69);
  });

  it('carries a credential for every principal that had one', () => {
    const withPassword = new Set(
      credentials.filter((credential) => credential.type === 'password').map((c) => c.subjectId),
    );
    const missing = identities
      .filter((identity) => !withPassword.has(identity.subjectId))
      .map((identity) => identity.userName);
    expect(missing, `principals with no password: ${missing.join(', ')}`).toEqual([]);
  });

  it('keeps the passwordless credential', () => {
    // One enrolled authenticator in the demo population, and it is the one that proves the whole
    // second factor survived the move.
    const keys = credentials.filter((credential) => credential.type === 'public_key');
    expect(keys).toHaveLength(1);
  });

  it('reproduces the role histogram exactly', () => {
    const histogram = identities.reduce<Record<string, number>>((counts, identity) => {
      const role = identity.roleName ?? 'none';
      counts[role] = (counts[role] ?? 0) + 1;
      return counts;
    }, {});
    // These become assignments. A role that silently gained or lost a holder is a permission change
    // nobody decided, which is why the histogram is exact and not a lower bound. `manager` went from
    // one holder to two deliberately: a sign-in screen offering a single named person cannot
    // demonstrate a role.
    expect(histogram).toEqual({
      customer: 56,
      level1_analyst: 2,
      level2_investigator: 2,
      security_auditor: 2,
      merchant_officer: 3,
      operations_officer: 2,
      manager: 2,
    });
  });

  it('recovered the demo password from a seeded hash, so the rest of this suite means something', () => {
    // If this fails, every sign-in below would fail for a reason unrelated to the migration, and the
    // gate would report a false alarm rather than a real one.
    expect(demoPassword, 'no candidate verified against a seeded hash').toBeTruthy();
  });
});

describe('v39 P5.8: every seeded principal signs in with today credentials', () => {
  it('signs in as every active principal, by user name and by email', async () => {
    expect(demoPassword).toBeTruthy();
    const failures: string[] = [];

    for (const identity of identities) {
      if (!identity.active) continue;

      const byUserName = await signIn(identity.userName, demoPassword as string);
      if (byUserName.statusCode !== 200) {
        failures.push(`${identity.userName} (user name): ${byUserName.statusCode}`);
        continue;
      }
      const body = byUserName.json();
      if (body.subjectId !== identity.subjectId) {
        // Resolving to the WRONG principal is worse than not resolving: it is a successful sign-in
        // as somebody else.
        failures.push(`${identity.userName}: resolved to ${body.subjectId}`);
      }

      if (identity.email) {
        const byEmail = await signIn(identity.email, demoPassword as string);
        if (byEmail.statusCode !== 200) failures.push(`${identity.email} (email): ${byEmail.statusCode}`);
      }
    }

    expect(failures, `sign-in failures: ${failures.slice(0, 10).join('; ')}`).toEqual([]);
  }, 600_000);

  it('establishes a session for each sign-in', async () => {
    const response = await signIn(identities[0].userName, demoPassword as string);
    expect(response.statusCode).toBe(200);
    const body = response.json();
    expect(body.sessionId).toBeTruthy();
    expect(body.method).toBe('password');
    expect(body.assuranceLevel).toBe('aal1');
  });

  it('refuses a wrong password without saying which part was wrong', async () => {
    const response = await signIn(identities[0].userName, 'not-the-password');
    expect(response.statusCode).toBe(401);
    // No enumeration: the body must not distinguish an unknown principal from a bad credential.
    expect(JSON.stringify(response.json())).not.toMatch(/password|user|unknown|exists/i);
  });

  it('refuses an unknown principal identically', async () => {
    const unknown = await signIn('nobody@nowhere.invalid', demoPassword as string);
    const wrong = await signIn(identities[0].userName, 'not-the-password');
    // Byte-identical, because a difference here is an account-enumeration oracle whatever the
    // intention behind it.
    expect(unknown.statusCode).toBe(wrong.statusCode);
    expect(unknown.json()).toEqual(wrong.json());
  });

  it('refuses a principal from another realm', async () => {
    // Realm isolation at the authentication step, before any token exists: a principal seeded in one
    // realm is simply not present in another, and that is what makes the boundary structural.
    const otherRealm = realmName === 'leafypay' ? 'bankcore' : 'leafypay';
    const response = await app.inject({
      method: 'POST',
      url: `/realms/${otherRealm}/login`,
      payload: { login: identities[0].userName, password: demoPassword as string },
    });
    expect(response.statusCode).toBe(401);
  });
});
