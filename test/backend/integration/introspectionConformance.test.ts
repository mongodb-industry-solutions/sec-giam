// v41 P7: introspection answers the question it exists to answer, and revocation says nothing.
//
// The defect worth naming is D18. Revocation was implemented as session deletion ONLY, so a grant a
// person withdrew while their session stayed live was reported `active: true` by the endpoint whose
// entire purpose is to be authoritative about revocation. Somebody could take an application's
// access away in the console and the application would keep working until the token expired, which
// is precisely the failure the centralised model is supposed to prevent.
import { describe, it, expect, beforeAll } from 'vitest';
import { clientSecretFor } from '@leafypay/platform-links';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';

/**
 * A CONFIDENTIAL client, because introspection and revocation require the caller to authenticate.
 *
 * An unauthenticated introspection endpoint is an oracle for token validity, so the public console
 * client cannot be used here and that is correct rather than inconvenient.
 */
const CLIENT = 'leafypay-backend';

function basic(): string {
  return `Basic ${Buffer.from(`${CLIENT}:${clientSecretFor(CLIENT)}`).toString('base64')}`;
}

async function machineToken(): Promise<string> {
  const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
    body: new URLSearchParams({ grant_type: 'client_credentials' }),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) return '';
  return (await response.json() as { access_token?: string }).access_token ?? '';
}

async function introspect(token: string) {
  const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
    body: new URLSearchParams({ token }),
    signal: AbortSignal.timeout(20000),
  });
  return response.json() as Promise<Record<string, unknown>>;
}

describe('v41 P7: introspection and revocation follow RFC 7662 and RFC 7009', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    token = await machineToken();
  });

  /**
   * RFC 7662 2.2. `aud` and `iss` are what a resource server MUST compare, and both were missing:
   * a caller relying on introspection alone learned that a token was active without learning who it
   * was for, so it could not perform audience validation at all.
   */
  it('returns the members a resource server needs to validate, not only that it is active', async () => {
    if (!live) return;
    expect(token, 'no token to introspect').toBeTruthy();
    const result = await introspect(token);

    expect(result.active).toBe(true);
    expect(result.aud, 'aud is what a resource server compares against its own').toBeDefined();
    expect(result.iss, 'iss is what says which authority minted it').toBeDefined();
    expect(result.jti, 'jti is what names the token in an incident').toBeDefined();
    expect(result.client_id).toBe(CLIENT);
    expect(result.token_type).toBe('Bearer');
  });

  /**
   * RFC 7662 2.2: an inactive token returns `{active: false}` AND NOTHING ELSE. Distinguishing
   * "expired" from "revoked" from "never existed" tells whoever is holding a stolen token which of
   * those they are holding.
   */
  it('says only `active: false` about a token it will not vouch for', async () => {
    if (!live) return;
    const result = await introspect('not-a-token-at-all');
    expect(result).toEqual({ active: false });
  });

  /**
   * RFC 7009 2.2 asks for 200 with an EMPTY body. It answered `{ revoked: true | false }`, which
   * contradicted the comment sitting three lines above it: reporting whether anything was revoked
   * tells a caller which of the tokens it holds are real, which is what answering identically was
   * supposed to prevent.
   */
  it('reveals nothing about whether a revocation found anything', async () => {
    if (!live) return;
    const revoke = (value: string) => fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic() },
      body: new URLSearchParams({ token: value }),
      signal: AbortSignal.timeout(20000),
    });

    const real = await revoke(await machineToken());
    const invented = await revoke('a-token-that-never-existed');

    expect(real.status).toBe(200);
    expect(invented.status).toBe(200);
    // Byte for byte the same answer, which is the only way the endpoint tells a caller nothing.
    expect(await real.text()).toBe('');
    expect(await invented.text()).toBe('');
  });

  it('refuses an unauthenticated caller, because an open introspection endpoint is an oracle', async () => {
    if (!live) return;
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token/introspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }),
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(401);
  });
});

describe('v41 P7: the discovery document advertises what is implemented, and nothing else', () => {
  let live = false;
  let metadata: Record<string, unknown> = {};

  beforeAll(async () => {
    try {
      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/.well-known/openid-configuration`, {
        signal: AbortSignal.timeout(5000),
      });
      metadata = await response.json() as Record<string, unknown>;
      live = true;
    } catch {
      live = false;
    }
  });

  /** D23. Declared in the response schema since v39 and never emitted, so nothing could discover it. */
  it('names the scopes a client may ask for', async () => {
    if (!live) return;
    expect(Array.isArray(metadata.scopes_supported)).toBe(true);
    expect(metadata.scopes_supported).toContain('openid');
  });

  /**
   * D24. It was the constant `['RS256']` while the key model declared RS256 and ES256, so the
   * document, the model and the signer could all disagree and nothing compared them.
   */
  it('names the algorithms the realm can actually sign with, read from the key set', async () => {
    if (!live) return;
    const advertised = metadata.id_token_signing_alg_values_supported as string[];
    const keySet = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/certs`)
      .then((response) => response.json()) as { keys: Array<{ alg?: string }> };
    const held = [...new Set(keySet.keys.map((key) => key.alg).filter(Boolean))].sort();
    expect(advertised).toEqual(held);
  });

  /** D25. The CIBA grant was advertised with none of the metadata a CIBA client must not guess at. */
  it('names the backchannel delivery modes, having advertised the grant', async () => {
    if (!live) return;
    expect(metadata.grant_types_supported).toContain('urn:openid:params:grant-type:ciba');
    expect(metadata.backchannel_token_delivery_modes_supported).toEqual(['poll', 'ping', 'push']);
    expect(metadata.backchannel_user_code_parameter_supported).toBe(false);
  });

  /** D27, and the reason the three private claims use short names: they are declared. */
  it('declares the private claims, which a consumer can otherwise only guess at', async () => {
    if (!live) return;
    const claims = metadata.claims_supported as string[];
    for (const claim of ['session_epoch', 'admin_realms', 'account_holder', 'txn', 'grant_id']) {
      expect(claims, claim).toContain(claim);
    }
  });

  /**
   * D26. RFC 8414 3.1 places the well-known segment BETWEEN the host and the path when the issuer
   * has path components, and only the OIDC-shaped location was served, so a client following that
   * RFC to the letter got a 404 from a server that does publish the document.
   */
  it('serves the metadata at the location RFC 8414 specifies, as well as the OIDC one', async () => {
    if (!live) return;
    const rfc8414 = await fetch(`${GIAM}/.well-known/oauth-authorization-server/api/v1/realms/${REALM}`, {
      signal: AbortSignal.timeout(5000),
    });
    expect(rfc8414.status).toBe(200);
    const document = await rfc8414.json() as { issuer?: string };
    expect(document.issuer).toBe(metadata.issuer);
  });
});
