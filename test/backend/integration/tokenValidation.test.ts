// v39 P8.5: both validation models, and the forgeries each must refuse.
//
// The plan requires negative tests for every classic JWT verification defect, and the reason each
// one gets its own test is that each is an ACCEPTED FORGERY rather than a failed parse. A verifier
// that merely happens not to handle them today is a verifier that accepts them the day a library
// changes a default.
//
// The two models answer different questions. Local verification answers "was this signed by the
// authority and is it within its lifetime". Introspection answers "is this active right now", which
// accounts for revocation and for a principal suspended since issuance. Neither is right in general.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { createPrivateKey, generateKeyPairSync, sign as cryptoSign } from 'crypto';
import { clientSecretFor } from '@leafypay/platform-links';

const REALM = 'leafypay';
const CLIENT_ID = 'leafypay-backend';
const CLIENT_SECRET = clientSecretFor('leafypay-backend');

let giam: FastifyInstance;
let issuer: string;

function segment(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** Builds a token with an arbitrary header, so the defects can actually be presented. */
function forge(header: Record<string, unknown>, claims: Record<string, unknown>, signature = 'x'): string {
  return `${segment(header)}.${segment(claims)}.${signature}`;
}

async function machineToken(): Promise<string> {
  const response = await giam.inject({
    method: 'POST',
    url: `/realms/${REALM}/protocol/openid-connect/token`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }).toString(),
  });
  return response.json().access_token;
}

async function introspect(token: string) {
  return giam.inject({
    method: 'POST',
    url: `/realms/${REALM}/protocol/openid-connect/token/introspect`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }).toString(),
  });
}

beforeAll(async () => {
  const { buildApp } = await import('../../../backend/src/app');
  giam = await buildApp();
  await giam.ready();

  const metadata = await giam.inject({ method: 'GET', url: `/realms/${REALM}/.well-known/openid-configuration` });
  issuer = metadata.json().issuer;
}, 180_000);

afterAll(async () => {
  await giam?.close();
});

describe('v39 P8.5: the centralised model answers what local verification cannot', () => {
  it('reports a freshly issued token as active', async () => {
    const response = await introspect(await machineToken());
    expect(response.statusCode).toBe(200);
    expect(response.json().active).toBe(true);
    expect(response.json().sub).toBe(CLIENT_ID);
  });

  it('cannot revoke a MACHINE token early, and says so honestly', async () => {
    /**
     * v40 changed what this endpoint can do for a `client_credentials` token, and the change is a
     * consequence of the design rather than a defect in it.
     *
     * Revocation is now the deletion of the SESSION a token belongs to, because no token is stored:
     * both kinds are JWTs, so a stored copy kept a redeemable artifact at rest for no information
     * the token did not already carry. And `client_credentials` creates no session, which is what
     * RFC 6749 section 4.4.3 requires.
     *
     * So a machine access token has nothing to revoke, and the bound on its exposure is its five
     * minute lifetime. That is the stated revocation objective, and pretending otherwise here would
     * make introspection lie about a token that still verifies.
     *
     * RFC 7009 still says respond 200: a revocation request for a token the server cannot act on is
     * not an error, and reporting one would tell a caller whether a token exists.
     *
     * Session-backed revocation IS immediate and is covered where it belongs: `singleLogout`
     * asserts the session document is gone, and the `sessionRevocation` unit suite asserts all four
     * revocation shapes plus reuse detection.
     */
    const token = await machineToken();
    expect((await introspect(token)).json().active).toBe(true);

    const revoked = await giam.inject({
      method: 'POST',
      url: `/realms/${REALM}/protocol/openid-connect/revoke`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ token, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }).toString(),
    });
    expect(revoked.statusCode).toBe(200);

    // Still active, because there was no session to delete. The five minute lifetime is the bound.
    expect(
      (await introspect(token)).json().active,
      'a machine token carries no session, so nothing revokes it before it expires',
    ).toBe(true);
  });

  it('carries no session on a machine token, which is why the above holds', async () => {
    // The reason, asserted rather than described: no `sid` claim means no session, and the session
    // is what revocation acts on.
    const token = await machineToken();
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    expect(claims.sid, 'client_credentials must not open a session').toBeUndefined();
  });

  it('answers 200 to a revocation whether or not anything was revoked', async () => {
    // RFC 7009 section 2.2, and not a formality: reporting "no such token" would tell a caller which
    // of the tokens it holds are real.
    const response = await giam.inject({
      method: 'POST',
      url: `/realms/${REALM}/protocol/openid-connect/revoke`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ token: 'not-a-token', client_id: CLIENT_ID, client_secret: CLIENT_SECRET }).toString(),
    });
    expect(response.statusCode).toBe(200);
  });

  it('gives one answer to every inactive token, whatever the reason', async () => {
    // Distinguishing expired from revoked from never-existed tells whoever holds a stolen token
    // which of those they are holding.
    const nonsense = await introspect('not-a-token');
    const forged = await introspect(forge({ alg: 'RS256', kid: 'nope' }, { sub: 'x' }));
    expect(nonsense.json()).toEqual({ active: false });
    expect(forged.json()).toEqual({ active: false });
  });

  it('refuses an unauthenticated introspection', async () => {
    // An open introspection endpoint is an oracle for token validity.
    const response = await giam.inject({
      method: 'POST',
      url: `/realms/${REALM}/protocol/openid-connect/token/introspect`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ token: 'anything' }).toString(),
    });
    expect(response.statusCode).toBe(401);
  });
});

describe('v39 P8.5: every classic verification defect is refused', () => {
  it('refuses alg none, which would make an unsigned token valid', async () => {
    const token = forge({ alg: 'none', kid: 'any' }, { iss: issuer, sub: 'attacker', exp: 9_999_999_999 }, '');
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses a symmetric algorithm, because the public key is published to everyone', async () => {
    // If HMAC were accepted, anybody holding the PUBLIC key could sign, and a public key is
    // published by design.
    const token = forge({ alg: 'HS256', kid: 'any' }, { iss: issuer, sub: 'attacker', exp: 9_999_999_999 });
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses a token that nominates its own verification key', async () => {
    // jku, jwk, x5u and x5c let a token assert its own authenticity. Presence alone is grounds for
    // refusal, not merely being ignored.
    for (const injected of [
      { jku: 'https://attacker.invalid/keys' },
      { jwk: { kty: 'RSA', n: 'x', e: 'AQAB' } },
      { x5u: 'https://attacker.invalid/cert' },
      { x5c: ['MIIB'] },
    ]) {
      const token = forge(
        { alg: 'RS256', kid: 'any', ...injected },
        { iss: issuer, sub: 'attacker', exp: 9_999_999_999 },
      );
      expect((await introspect(token)).json().active, `accepted a token carrying ${Object.keys(injected)[0]}`).toBe(false);
    }
  });

  it('refuses an unknown key id rather than resolving to whatever key is at hand', async () => {
    const token = forge({ alg: 'RS256', kid: 'a-key-that-does-not-exist' }, { iss: issuer, sub: 'attacker', exp: 9_999_999_999 });
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses a token with no key id at all', async () => {
    const token = forge({ alg: 'RS256' }, { iss: issuer, sub: 'attacker', exp: 9_999_999_999 });
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses a correctly shaped token signed by the wrong key', async () => {
    // The whole of the rest is right: algorithm, issuer, expiry, structure. Only the signer is
    // wrong, which is the case every other check would let through.
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const header = segment({ alg: 'RS256', typ: 'at+jwt', kid: 'attacker-key' });
    const payload = segment({ iss: issuer, sub: 'attacker', aud: CLIENT_ID, exp: 9_999_999_999 });
    const signature = cryptoSign('sha256', Buffer.from(`${header}.${payload}`), createPrivateKey(privateKey.export({ type: 'pkcs8', format: 'pem' }) as string));
    const token = `${header}.${payload}.${signature.toString('base64url')}`;
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses a token from another issuer', async () => {
    const token = forge(
      { alg: 'RS256', kid: 'any' },
      { iss: 'https://another-authority.invalid/realms/leafypay', sub: 'x', exp: 9_999_999_999 },
    );
    expect((await introspect(token)).json().active).toBe(false);
  });

  it('refuses an expired token', async () => {
    const token = forge({ alg: 'RS256', kid: 'any' }, { iss: issuer, sub: 'x', exp: 1 });
    expect((await introspect(token)).json().active).toBe(false);
  });
});

describe('v39 P8.5: the published key set carries public material only', () => {
  it('publishes no private parameter', async () => {
    const response = await giam.inject({ method: 'GET', url: `/realms/${REALM}/protocol/openid-connect/certs` });
    for (const key of response.json().keys) {
      for (const privateParameter of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k']) {
        expect(key[privateParameter], `the key set exposes ${privateParameter}`).toBeUndefined();
      }
    }
  });

  it('is cacheable, because a stale copy is safe', async () => {
    // An old public key can only validate signatures the authority itself produced, which is what
    // makes serving a stale set during an outage the right trade rather than a shortcut.
    const response = await giam.inject({ method: 'GET', url: `/realms/${REALM}/protocol/openid-connect/certs` });
    expect(response.headers['cache-control']).toContain('max-age');
  });
});
