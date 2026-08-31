import { describe, it, expect } from 'vitest';
import { clientSecretFor, CLIENT_SECRET_REFS } from '@leafypay/platform-links';

// The client secret derivation is a CROSS-REPO CONTRACT: GIAM seeds the secret, and LeafyPay and the
// merchant app derive the same value from their own copy of packages/platform-links. Without pinned
// vectors a drift between the copies is invisible until a token request is refused in a deployment.
//
// If one of these fails, the derivation changed. That is allowed, but both repositories have to be
// updated in the same change and every seeded database re-seeded.
describe('client secret derivation (cross-repo contract)', () => {
  // Every client id in backend/data/clients.json, with the secret the seeder writes for it.
  const VECTORS: Record<string, string> = {
    'oauth001-0000-4000-8000-000000000001': 'oZ0HWjtO2HGgLN3RMVmqvau5InhNdQpY5ouDzl7TCOU',
    'f1dc0169-4f90-402c-adc8-f7e2c5c0fc7d': 'ZgGxaRICNAQbkJflGt5G_B3XIcmCrSYGRJ55C5G1KRU',
    'leafypay-backend': 'Ef4uUbXNVnQ8o5Fzl5sPPbS6yVeGzYgRUPnyWNVB8uM',
    'leafypay-psp': 'I5-J0pqHCCK9sY8pobFiYBdALRKnKZVIkzwAyXpkftg',
    'bankcore-backend': 'QGdvGlJzyiUJjpTjzQdikA88bCCCieyUlsTLgC0alyI',
    'bankcore-console': 'ZWcHjBdv5wOEpXvB-l2AZcSQRf95CuVXBeGsuZFUu4I',
    'giam-console': '5CSnsINgkqUVNTYS1-WMk-qW0sXes-c48u1sZ2T-Y60',
    'leafypay-simulator': 'U7WeNc5eVnvI8l93J34NlR5tZdqoyMYHfTsUPrM_zao',
    'another-tpp': 'arnqT2_yRIITQ14e-16hwFUaYkFv7tHYf-xt_1S4j7k',
  };

  // An empty environment, so a pinned override in the developer's shell cannot mask a drift.
  const NO_ENV = {} as NodeJS.ProcessEnv;

  for (const [clientId, expected] of Object.entries(VECTORS)) {
    it(`derives the pinned secret for ${clientId}`, () => {
      expect(clientSecretFor(clientId, NO_ENV)).toBe(expected);
    });
  }

  it('is deterministic and url-safe base64 of a sha256 digest', () => {
    const secret = clientSecretFor('giam-console', NO_ENV);
    expect(secret).toBe(clientSecretFor('giam-console', NO_ENV));
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  // Length prefixing is what stops two different ids producing the same hash input.
  it('separates ids that would otherwise concatenate identically', () => {
    expect(clientSecretFor('ab', NO_ENV)).not.toBe(clientSecretFor('a', { ...NO_ENV, b: 'x' }));
    expect(clientSecretFor('a:b', NO_ENV)).not.toBe(clientSecretFor('a', NO_ENV));
  });

  it('lets an operator pin a secret by environment variable', () => {
    for (const [clientId, ref] of Object.entries(CLIENT_SECRET_REFS)) {
      expect(clientSecretFor(clientId, { [ref]: 'pinned-value' } as NodeJS.ProcessEnv)).toBe('pinned-value');
      // Blank is not a value: it falls back to the derivation rather than seeding an empty secret.
      expect(clientSecretFor(clientId, { [ref]: '   ' } as NodeJS.ProcessEnv)).toBe(VECTORS[clientId]);
    }
  });
});
