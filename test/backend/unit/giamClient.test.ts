// v39 P8.4: the shared verifier, and the behaviours that only appear under failure.
//
// One implementation rather than one per application, because four verifiers is four opinions about
// which forgeries to refuse and they will not stay the same.
//
// The cases below are the ones that never appear in normal operation and decide what happens when
// something goes wrong: an unreachable authority, a rotated key, a revoked token, a burst of
// concurrent requests. Each is driven with an injected fetch, so the behaviour is exercised rather
// than assumed.
import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPairSync, createPublicKey, createPrivateKey, sign as cryptoSign, KeyObject } from 'crypto';
import { GiamClient, isLogoutToken } from '../../../../packages/giam-client/src/index';

const ISSUER = 'https://authority.test/realms/acme';
const AUDIENCE = 'orders-api';

interface TestKey {
  kid: string;
  privateKey: KeyObject;
  jwk: Record<string, unknown>;
}

function makeKey(kid: string): TestKey {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const priv = createPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
  const jwk = createPublicKey(priv).export({ format: 'jwk' }) as Record<string, unknown>;
  return { kid, privateKey: priv, jwk: { ...jwk, kid, use: 'sig', alg: 'RS256' } };
}

function mint(key: TestKey, claims: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const head = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'at+jwt', kid: key.kid, ...header })).toString('base64url');
  const body = Buffer.from(JSON.stringify({
    iss: ISSUER, aud: AUDIENCE, sub: 'ada', iat: now, exp: now + 900, ...claims,
  })).toString('base64url');
  const signature = cryptoSign('sha256', Buffer.from(`${head}.${body}`), key.privateKey);
  return `${head}.${body}.${signature.toString('base64url')}`;
}

/** A controllable authority: counts calls, can be made to fail, can rotate its key set. */
function makeAuthority(keys: TestKey[]) {
  const state = { keys, discoveryCalls: 0, jwksCalls: 0, failing: false };
  const fetchImpl = (async (url: string | URL) => {
    const href = String(url);
    if (state.failing) throw new Error('authority unreachable');
    if (href.endsWith('/.well-known/openid-configuration')) {
      state.discoveryCalls += 1;
      return new Response(JSON.stringify({ issuer: ISSUER, jwks_uri: `${ISSUER}/protocol/openid-connect/certs` }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    if (href.endsWith('/certs')) {
      state.jwksCalls += 1;
      return new Response(JSON.stringify({ keys: state.keys.map((key) => key.jwk) }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    return new Response('{}', { status: 404 });
  }) as unknown as typeof fetch;
  return { state, fetchImpl };
}

let key: TestKey;
let authority: ReturnType<typeof makeAuthority>;
let client: GiamClient;

beforeEach(() => {
  key = makeKey('key-1');
  authority = makeAuthority([key]);
  client = new GiamClient({ issuerUrl: ISSUER, audience: AUDIENCE, fetchImpl: authority.fetchImpl });
});

describe('v39 P8.4: the ordinary path', () => {
  it('discovers, fetches and verifies', async () => {
    const claims = await client.verify(mint(key, {}));
    expect(claims?.sub).toBe('ada');
    expect(authority.state.discoveryCalls).toBe(1);
    expect(authority.state.jwksCalls).toBe(1);
  });

  it('costs nothing per request while the cache is warm', async () => {
    for (let i = 0; i < 10; i += 1) await client.verify(mint(key, {}));
    // The defining property of local verification: zero network traffic per request.
    expect(authority.state.jwksCalls).toBe(1);
    expect(client.metrics.cacheHits).toBeGreaterThan(5);
  });

  it('makes one request for a burst of concurrent verifications', async () => {
    // A cold cache under load must not become a stampede against the authority.
    await Promise.all(Array.from({ length: 20 }, () => client.verify(mint(key, {}))));
    expect(authority.state.jwksCalls).toBe(1);
  });
});

describe('v39 P8.4: rotation needs no deploy', () => {
  it('picks up a new key on an unknown key id', async () => {
    await client.verify(mint(key, {}));
    expect(authority.state.jwksCalls).toBe(1);

    // The authority rotates: a new key signs, the old one stays published.
    const rotated = makeKey('key-2');
    authority.state.keys = [key, rotated];

    const claims = await client.verify(mint(rotated, {}));
    expect(claims?.sub).toBe('ada');
    // Exactly one refetch, triggered by the unknown key id rather than by a redeploy.
    expect(authority.state.jwksCalls).toBe(2);
  });

  it('still accepts a token signed by the retired key', async () => {
    const rotated = makeKey('key-2');
    authority.state.keys = [key, rotated];
    await client.verify(mint(rotated, {}));
    // Removing a key still in use is the one operational mistake that breaks this model, so a
    // retired key must keep verifying until every token it signed has expired.
    expect((await client.verify(mint(key, {})))?.sub).toBe('ada');
  });

  it('does not refetch repeatedly for a forged key id', async () => {
    const attacker = makeKey('forged');
    await client.verify(mint(key, {}));
    const before = authority.state.jwksCalls;

    for (let i = 0; i < 10; i += 1) {
      expect(await client.verify(mint(attacker, {}))).toBeNull();
    }
    // Rate limited per key: a forged id cannot be used to hammer the authority.
    expect(authority.state.jwksCalls - before).toBeLessThanOrEqual(1);
  });
});

describe('v39 P8.4: an unreachable authority does not close the application', () => {
  it('serves from a stale cache and keeps verifying', async () => {
    const warm = new GiamClient({
      issuerUrl: ISSUER, audience: AUDIENCE, jwksCacheSeconds: 0, fetchImpl: authority.fetchImpl,
    });
    expect(await warm.verify(mint(key, {}))).toBeTruthy();

    authority.state.failing = true;

    // The alternative is a total outage of this application every time the authority blinks, and
    // serving stale is safe: an old public key validates only what the authority itself signed.
    const claims = await warm.verify(mint(key, {}));
    expect(claims?.sub).toBe('ada');
    expect(warm.metrics.staleServes).toBeGreaterThan(0);
  });

  it('refuses when it has never had a key set at all', async () => {
    authority.state.failing = true;
    const cold = new GiamClient({ issuerUrl: ISSUER, audience: AUDIENCE, fetchImpl: authority.fetchImpl });
    // Nothing to be stale about. Refusing is the only honest answer.
    expect(await cold.verify(mint(key, {}))).toBeNull();
  });

  it('fails CLOSED on introspection, unlike local verification', async () => {
    authority.state.failing = true;
    // Introspection is used where being wrong is expensive to undo, so an unanswerable question
    // must not be treated as a yes. The opposite posture to local verification, deliberately.
    const result = await client.introspect('any', { clientId: 'c', clientSecret: 's' });
    expect(result.active).toBe(false);
  });
});

describe('v39 P8.4: revocation reaches local verification', () => {
  it('refuses a token whose identifier was revoked out of band', async () => {
    const token = mint(key, { jti: 'token-1' });
    expect(await client.verify(token)).toBeTruthy();

    client.revoke('token-1', Math.floor(Date.now() / 1000) + 900);

    // This is what makes the hybrid model honest rather than a fudge: the revocation is respected
    // within the delivery latency of the notification, not within the token lifetime.
    expect(await client.verify(token)).toBeNull();
    expect(client.metrics.failuresByCause.revoked).toBe(1);
  });

  it('drops a revocation once the token it named has expired', async () => {
    client.revoke('expired-token', Math.floor(Date.now() / 1000) - 10);
    client.revoke('live-token', Math.floor(Date.now() / 1000) + 900);
    // Kept forever, the list grows without bound; after expiry the signature check refuses the token
    // anyway, so the entry buys nothing.
    expect(client.isRevoked('expired-token')).toBe(false);
    expect(client.isRevoked('live-token')).toBe(true);
  });
});

describe('v39 P8.4: the forgeries, refused by cause', () => {
  it('refuses each classic defect and records why', async () => {
    const cases: Array<[string, string]> = [
      ['unexpected_alg', mint(key, {}, { alg: 'none' })],
      ['unexpected_alg', mint(key, {}, { alg: 'HS256' })],
      ['header_key_injection', mint(key, {}, { jku: 'https://attacker.invalid/keys' })],
      ['header_key_injection', mint(key, {}, { jwk: { kty: 'RSA' } })],
      ['header_key_injection', mint(key, {}, { x5u: 'https://attacker.invalid' })],
      ['header_key_injection', mint(key, {}, { x5c: ['MIIB'] })],
      ['wrong_issuer', mint(key, { iss: 'https://elsewhere.invalid/realms/acme' })],
      ['wrong_audience', mint(key, { aud: 'another-api' })],
      ['expired', mint(key, { exp: 1 })],
    ];

    for (const [cause, token] of cases) {
      expect(await client.verify(token), `accepted a token that should fail as ${cause}`).toBeNull();
    }
    for (const [cause] of cases) {
      expect(client.metrics.failuresByCause[cause], `no failure recorded for ${cause}`).toBeGreaterThan(0);
    }
  });

  it('refuses a correctly shaped token signed by the wrong key', async () => {
    const attacker = makeKey('key-1');
    // Same key id as the real one, so only the signature distinguishes them. This is the case every
    // other check would let through.
    expect(await client.verify(mint(attacker, {}))).toBeNull();
    expect(client.metrics.failuresByCause.bad_signature).toBe(1);
  });
});

describe('v39 P8.4: a logout notification is recognisable', () => {
  it('identifies one by its event member rather than by shape', () => {
    expect(isLogoutToken({ events: { 'http://schemas.openid.net/event/backchannel-logout': {} } })).toBe(true);
    expect(isLogoutToken({ sub: 'ada' })).toBe(false);
  });
});
