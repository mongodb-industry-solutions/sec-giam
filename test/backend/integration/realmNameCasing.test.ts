/**
 * A realm and a domain are addressed WITHOUT case.
 *
 * A slug travels in a URL path, in a pasted link, in a fixture and in a form, and `LeafyIdp`,
 * `leafyidp` and `LEAFYIDP` are one realm to everybody except a byte comparison. A sign-in that
 * fails because a link capitalised a letter produces an error nobody can diagnose, so this pins
 * the behaviour rather than leaving it to whichever spelling the fixture happened to use.
 *
 * Runs in process against the real database, because the property being tested is half a query
 * and half an index: `RealmService.byName` passes the `CASE_INSENSITIVE` collation and
 * `name_unique` and `aliases` are declared with it. A mock of either would prove nothing.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import type { FastifyInstance } from 'fastify';

const DATA = resolve(__dirname, '../../../backend/data');
const fixture = (JSON.parse(readFileSync(resolve(DATA, 'realms.json'), 'utf8')) as Array<{
  name: string;
  aliases?: string[];
  domains: Array<{ name: string; protocol: string }>;
}>)[0];

let app: FastifyInstance;

beforeAll(async () => {
  const { buildApp } = await import('../../../backend/src/app');
  app = await buildApp();
  await app.ready();
}, 120_000);

afterAll(async () => {
  await app?.close();
});

/** Every spelling of one name that a caller might plausibly send. */
function casings(name: string): string[] {
  return [...new Set([name, name.toLowerCase(), name.toUpperCase()])];
}

describe('a realm resolves by name whatever its casing', () => {
  it.each(casings(fixture.name))('resolves "%s" to the same realm', async (spelling) => {
    const response = await app.inject({ method: 'GET', url: `/api/v1/realms/${spelling}/login-context` });
    expect(response.statusCode, `"${spelling}" did not resolve`).toBe(200);
    // The RECORD's own spelling comes back, not the caller's: resolution is case-insensitive,
    // the stored name is not rewritten by whoever asked for it.
    expect((response.json() as { realm: string }).realm).toBe(fixture.name);
  });

  it.each((fixture.aliases ?? []).flatMap(casings))('resolves the alias "%s" too', async (spelling) => {
    const response = await app.inject({ method: 'GET', url: `/api/v1/realms/${spelling}/login-context` });
    expect(response.statusCode, `alias "${spelling}" did not resolve`).toBe(200);
    expect((response.json() as { realm: string }).realm).toBe(fixture.name);
  });

  it('still refuses a realm that does not exist, in any casing', async () => {
    // The point of the collation is to widen how one name is spelled, not what counts as a name.
    for (const spelling of casings('no-such-realm-here')) {
      const response = await app.inject({ method: 'GET', url: `/api/v1/realms/${spelling}/login-context` });
      expect(response.statusCode, `"${spelling}" resolved to something`).toBe(404);
    }
  });

  it('offers the same domains however the realm was spelled', async () => {
    const answers = await Promise.all(casings(fixture.name).map(async (spelling) => {
      const response = await app.inject({ method: 'GET', url: `/api/v1/realms/${spelling}/login-context` });
      return (response.json() as { providers: Array<{ name: string }> }).providers.map((p) => p.name).sort();
    }));
    for (const offered of answers) expect(offered).toEqual(answers[0]);
    expect(answers[0]).toEqual(fixture.domains.map((domain) => domain.name).sort());
  });
});
