/**
 * An application's addresses live on its own registration, and are bound when the record is read.
 *
 * The alternative was a per-application variable in the authority's own configuration, which fails
 * on the thing that matters here: adding an integration would be a redeployment of the authority
 * rather than a registration, and the authority would hold facts about applications that each
 * application already knows about itself. The shape is the one provider arrangements already use,
 * `baseUrlByEnvironment`, selected by the single name the deployment already declares.
 *
 * Binding at READ time and not at seed time is the other half: the same database is restored across
 * environments, so a host resolved when the record was written is a host from another cluster.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { resolveClientLogoUri } from '../../../backend/src/modules/oauth/models/client.model';

const DATA = resolve(__dirname, '../../../backend/data');

interface ClientFixture {
  clientId: string;
  clientName: string;
  logoUri?: string;
  baseUrlByEnvironment?: Record<string, string>;
}

const fixtures = JSON.parse(readFileSync(resolve(DATA, 'clients.json'), 'utf8')) as ClientFixture[];

describe('a client logo is bound to the environment the authority is running as', () => {
  it('resolves a stored path against the address for this environment', () => {
    const metadata = {
      logoUri: '/icon.png',
      baseUrlByEnvironment: {
        development: 'http://localhost:9999',
        staging: 'https://staging.example',
        production: 'https://example.com',
      },
    } as const;
    expect(resolveClientLogoUri(metadata, { NODE_ENV: 'development' })).toBe('http://localhost:9999/icon.png');
    expect(resolveClientLogoUri(metadata, { NODE_ENV: 'staging' })).toBe('https://staging.example/icon.png');
    expect(resolveClientLogoUri(metadata, { NODE_ENV: 'production' })).toBe('https://example.com/icon.png');
  });

  it('joins exactly one slash, whichever way the two halves were written', () => {
    const base = { baseUrlByEnvironment: { staging: 'https://staging.example/' } };
    expect(resolveClientLogoUri({ ...base, logoUri: '/icon.png' }, { NODE_ENV: 'staging' }))
      .toBe('https://staging.example/icon.png');
    expect(resolveClientLogoUri({ ...base, logoUri: 'icon.png' }, { NODE_ENV: 'staging' }))
      .toBe('https://staging.example/icon.png');
  });

  it('leaves an absolute logo alone, because a third party owns its own host', () => {
    const declared = 'https://acme.example/logo.svg';
    expect(resolveClientLogoUri({ logoUri: declared }, { NODE_ENV: 'staging' })).toBe(declared);
  });

  /**
   * Dropped rather than half-resolved. The consent screen then shows its neutral placeholder, which
   * is the honest answer; a path served as if it were a URL would resolve against the AUTHORITY's
   * own origin and ask it for an icon it does not have.
   */
  it('reports no logo at all when this environment has no address for the application', () => {
    const metadata = { logoUri: '/icon.png', baseUrlByEnvironment: { production: 'https://example.com' } };
    expect(resolveClientLogoUri(metadata, { NODE_ENV: 'staging' })).toBeUndefined();
    expect(resolveClientLogoUri({ logoUri: '/icon.png' }, { NODE_ENV: 'staging' })).toBeUndefined();
  });

  it('every seeded application that declares a logo path also declares where it answers', () => {
    const offenders = fixtures
      .filter((client) => client.logoUri && !/^https?:\/\//i.test(client.logoUri))
      .filter((client) => {
        const declared = client.baseUrlByEnvironment ?? {};
        return !declared.development || !declared.staging || !declared.production;
      })
      .map((client) => client.clientName);
    expect(offenders, `a logo path with no address to bind it to: ${offenders.join(', ')}`).toEqual([]);
  });

  it('declares an address for every environment, or none, on every seeded application', () => {
    // A map that names one environment and not the others is almost always a half-finished edit, and
    // the symptom is an application whose logo appears on a laptop and nowhere else.
    const partial = fixtures
      .filter((client) => client.baseUrlByEnvironment)
      .filter((client) => Object.keys(client.baseUrlByEnvironment!).length !== 3)
      .map((client) => client.clientName);
    expect(partial, `declares some environments but not all: ${partial.join(', ')}`).toEqual([]);
  });
});
