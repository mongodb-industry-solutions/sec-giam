// v39 P11.6: the extraction is complete, and stays complete.
//
// Deleting the identity implementation once is easy. Keeping it deleted is the hard part: the next
// person who needs a user lookup, a role check or a token will write one, because writing one is
// always the shortest path from where they are standing. Every rule below exists so that shortcut
// fails in CI rather than being noticed in review, or not noticed at all.
//
// These are assertions about SOURCE, deliberately. A runtime test would prove the routes are gone; a
// source test proves the CAPABILITY is gone, which is the thing that would otherwise creep back.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'fs';
import { resolve, join, relative } from 'path';

const ROOT = resolve(__dirname, '../../../..');
const CONSUMERS = [
  { name: 'LeafyPay', root: resolve(ROOT, 'psp/backend') },
  { name: 'BankCore', root: resolve(ROOT, 'bank/backend') },
];

/** Every TypeScript source file under a directory, excluding what is not ours. */
function sources(root: string): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      if (entry === 'node_modules' || entry === 'dist' || entry === '.next') continue;
      const path = join(dir, entry);
      if (statSync(path).isDirectory()) walk(path);
      else if (path.endsWith('.ts') && !path.endsWith('.d.ts')) found.push(path);
    }
  };
  walk(join(root, 'src'));
  walk(join(root, 'bin'));
  return found;
}

function read(path: string): string {
  return readFileSync(path, 'utf8');
}

/** Comments explain what was removed and why, so they must not trip the checks below. */
function withoutComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

describe('v39 P11.6: no consumer implements identity any more', () => {
  it('has no identity module left in either backend', () => {
    for (const consumer of CONSUMERS) {
      const modules = join(consumer.root, 'src/modules/identity');
      if (!existsSync(modules)) continue;

      // A surviving directory is allowed only for the compatibility proxy and the user's own view of
      // their authorisations, both of which forward rather than decide.
      const permitted = new Set(['authorityProxy.controller.ts', 'consentGrants.controller.ts', 'index.ts']);
      const remaining = sources(consumer.root)
        .filter((path) => path.includes(`${'src'}${'/'}modules${'/'}identity`) || path.includes('src\\modules\\identity'))
        .map((path) => path.split(/[\\/]/).pop() as string)
        .filter((file) => !permitted.has(file));

      expect(remaining, `${consumer.name} still has identity implementation: ${remaining.join(', ')}`).toEqual([]);
    }
  });

  it('mints no token anywhere', () => {
    // The one legitimate exception is a security event token sent to a third party under Open
    // Banking: a regulated business notification the bank owns, not identity issuance. It is named
    // rather than pattern-matched, so a second signer cannot hide behind the same allowance.
    const ALLOWED_SIGNERS = ['eventNotification.service.ts', 'bankSigningKey.service.ts'];

    for (const consumer of CONSUMERS) {
      const offenders = sources(consumer.root)
        .filter((path) => !ALLOWED_SIGNERS.some((allowed) => path.endsWith(allowed)))
        .filter((path) => /\bjwt\.sign\b|\bSignJWT\b|createSign\s*\(/.test(withoutComments(read(path))))
        .map((path) => relative(ROOT, path));

      expect(offenders, `${consumer.name} signs tokens: ${offenders.join(', ')}`).toEqual([]);
    }
  });

  it('stores no PRINCIPAL credential material', () => {
    /**
     * The exception, named rather than pattern-matched.
     *
     * A provider integration key is a credential this platform issues to an EXTERNAL provider so it
     * can call back in. It authenticates a system to this one; it is not a principal's credential
     * and it grants no identity. The distinction is real, and the rule this test enforces is about
     * who may say WHO SOMEBODY IS, which that key never does.
     */
    const ALLOWED_STORES = [
      'integrationRegistry.service.ts',
      // A third-party provider registration under Open Banking. The bank is the regulated party that
      // must hold this registry, and the credential authenticates an INSTITUTION to it. It says
      // nothing about who a person is, which is the line this rule actually draws.
      'tppRegistration.service.ts',
      'seedTppRegistrations.ts',
    ];

    for (const consumer of CONSUMERS) {
      const offenders = sources(consumer.root)
        .filter((path) => !ALLOWED_STORES.some((allowed) => path.endsWith(allowed)))
        .filter((path) => {
          const source = withoutComments(read(path));
          // Hashing or comparing a secret means this service is deciding whether a credential is
          // right, which is the single thing the extraction moved.
          return /bcrypt\.(hash|compare)|argon2\.(hash|verify)|scryptSync\s*\(/.test(source);
        })
        .map((path) => relative(ROOT, path));

      expect(offenders, `${consumer.name} verifies credentials: ${offenders.join(', ')}`).toEqual([]);
    }
  });

  it('seeds no principals, roles or credentials', () => {
    for (const consumer of CONSUMERS) {
      const seedDir = join(consumer.root, 'src/vendors/seed');
      if (!existsSync(seedDir)) continue;

      const forbidden = /seed(Users|Roles|AuthDomains|EnrolledCredentials|Staff|Principals)\.ts$/;
      const offenders = readdirSync(seedDir).filter((file) => forbidden.test(file));
      expect(offenders, `${consumer.name} still seeds identity: ${offenders.join(', ')}`).toEqual([]);
    }
  });

  it('creates no identity collection in its own setup', () => {
    // A consumer that creates these has a place to write principals to, and a place to write to is
    // eventually written to.
    const forbidden = [
      'customerAuthenticationAssessment',
      'partyEnrolledCredential',
      'partyBackchannelAuthentication',
      'partyAuthConsent',
      'authenticationDomain',
    ];

    for (const consumer of CONSUMERS) {
      const setup = join(consumer.root, 'src/vendors/setup/createCollections.ts');
      if (!existsSync(setup)) continue;

      const source = withoutComments(read(setup));
      const found = forbidden.filter((collection) => source.includes(collection));
      expect(found, `${consumer.name} creates identity collections: ${found.join(', ')}`).toEqual([]);
    }
  });

  it('holds no signing key for IDENTITY and publishes no issuer metadata', () => {
    /**
     * The exception, named.
     *
     * The bank signs its Open Banking event notifications and publishes the public half at a JWKS
     * URL. That is a regulated obligation it owns as a BANK: a receiving third party has to verify
     * those notifications through a published key set, exactly as it would against a real
     * institution, and making the client's verification unrealistic would be the wrong
     * simplification.
     *
     * It is not identity issuance. That key never signs a token asserting who somebody is, and the
     * metadata it publishes is a key set rather than issuer configuration. The rule stands: no
     * consumer publishes `/.well-known/openid-configuration`, because that document is a claim to
     * be an authorization server.
     */
    const ALLOWED_KEY_HOLDERS = ['bankSigningKey.service.ts'];

    for (const consumer of CONSUMERS) {
      const offenders = sources(consumer.root)
        .filter((path) => !ALLOWED_KEY_HOLDERS.some((allowed) => path.endsWith(allowed)))
        .filter((path) => {
          const source = withoutComments(read(path));
          // Publishing a key set is claiming to be an issuer. Verifying against somebody else's is
          // the opposite, and is what these services should be doing.
          return /generateKeyPairSync\s*\(/.test(source)
            || /['"`]\/\.well-known\/openid-configuration['"`]/.test(source);
        })
        .map((path) => relative(ROOT, path));

      expect(offenders, `${consumer.name} acts as an issuer: ${offenders.join(', ')}`).toEqual([]);
    }
  });

  it('decides no permission from a stored role table', () => {
    for (const consumer of CONSUMERS) {
      // The catalog of what CAN be permitted is fine and belongs to a resource server. A table of who
      // HOLDS what is the authority's, and a consumer holding one is a second decision point that
      // will disagree with the first.
      const offenders = sources(consumer.root)
        .filter((path) => /BUILTIN_ROLES|ROLE_PERMISSIONS\s*[:=]/.test(withoutComments(read(path))))
        .map((path) => relative(ROOT, path));

      expect(offenders, `${consumer.name} holds a role table: ${offenders.join(', ')}`).toEqual([]);
    }
  });
});

describe('v39 P11.6: what replaced it is actually wired up', () => {
  it('verifies tokens against the authority in both backends', () => {
    for (const consumer of CONSUMERS) {
      const verifier = sources(consumer.root).find((path) => path.endsWith('tokenVerifier.ts'));
      expect(verifier, `${consumer.name} has no token verifier`).toBeTruthy();

      const source = read(verifier as string);
      // The classic verification defects, refused explicitly. Each is an accepted forgery rather
      // than a failed parse, so absence of the check is absence of the security property.
      expect(source, `${consumer.name} does not refuse alg none`).toMatch(/RS256/);
      expect(source, `${consumer.name} does not refuse a self-nominated key`).toMatch(/jku|jwk|x5u/);
    }
  });

  it('keeps the compatibility proxy honest', () => {
    const proxy = resolve(ROOT, 'psp/backend/src/modules/identity/controllers/authorityProxy.controller.ts');
    if (!existsSync(proxy)) return;

    const source = withoutComments(read(proxy));
    // The moment it inspects a token it stops being a proxy and starts being a second authorization
    // server, which is the failure this whole phase exists to prevent.
    expect(source, 'the proxy verifies tokens').not.toMatch(/verifyAccessToken|jwt\.verify/);
    expect(source, 'the proxy has no allowlist').toMatch(/FORWARDED/);
  });
});
