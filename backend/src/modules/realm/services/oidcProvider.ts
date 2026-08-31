import { Db } from 'mongodb';
import { createHash, timingSafeEqual } from 'crypto';
import type { IdentityProviderAdapter } from '../../../shared/ports';
import { IDENTITY_PROVIDER_COLLECTION } from '../../../shared/models/collections';
import { IdentityProviderRecord } from '../models/identityProvider.model';

/**
 * Federating a third-party OpenID provider.
 *
 * The whole argument for brokering lives here. Adding an upstream provider is a RECORD plus a claim
 * mapping: no application code, no application deployment, no application restart, and none of the
 * five applications learns that a second identity source exists. The alternative is each of them
 * implementing OIDC again, and then SAML again, each with its own subtly different verification.
 *
 * What this deliberately does NOT do is trust an upstream token because it parses. It is verified
 * against the provider's published keys and its issuer and audience are checked, exactly as a
 * resource server verifies one of ours. A broker that skips that turns every federated provider into
 * a way to assert any identity it likes.
 */

let boundDb: Db | null = null;

export function bindIdentityProviders(db: Db): void {
  boundDb = db;
}

async function load(providerId: string): Promise<IdentityProviderRecord> {
  if (!boundDb) throw new Error('Identity providers are not bound to a database');
  const provider = await boundDb
    .collection<IdentityProviderRecord>(IDENTITY_PROVIDER_COLLECTION)
    .findOne({ providerId }, { projection: { _id: 0 } });
  if (!provider) throw new Error(`No identity provider ${providerId}`);
  if (!provider.enabled) throw new Error(`Identity provider ${provider.name} is not enabled`);
  return provider;
}

/** Discovery, so a provider is configured by its issuer rather than by four hand-copied URLs. */
async function endpoints(provider: IdentityProviderRecord): Promise<{
  authorization: string; token: string; jwks: string; issuer: string;
}> {
  const configured = provider.config;
  if (configured.authorizationEndpoint && configured.tokenEndpoint && configured.jwksUri && configured.issuer) {
    return {
      authorization: configured.authorizationEndpoint,
      token: configured.tokenEndpoint,
      jwks: configured.jwksUri,
      issuer: configured.issuer,
    };
  }
  if (!configured.issuer) throw new Error(`Provider ${provider.name} has no issuer configured`);

  const response = await fetch(`${configured.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`, {
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`Discovery failed for ${provider.name}`);
  const document = await response.json();
  return {
    authorization: document.authorization_endpoint,
    token: document.token_endpoint,
    jwks: document.jwks_uri,
    issuer: document.issuer,
  };
}

/**
 * Verifies an upstream id token against the provider's published keys.
 *
 * The same refusals the local verifier makes, for the same reasons: an unsigned token, a symmetric
 * algorithm, or a token nominating the key that validates it are each an accepted forgery rather
 * than a failed parse.
 */
async function verifyUpstream(
  idToken: string,
  expected: { issuer: string; audience: string; jwksUri: string; nonce?: string },
): Promise<Record<string, unknown>> {
  const [rawHeader, rawPayload, rawSignature] = idToken.split('.');
  if (!rawHeader || !rawPayload || !rawSignature) throw new Error('Malformed upstream token');

  const header = JSON.parse(Buffer.from(rawHeader, 'base64url').toString());
  if (header.alg === 'none' || typeof header.alg !== 'string' || !header.alg.startsWith('RS')) {
    throw new Error('Upstream token algorithm is not acceptable');
  }
  if (header.jku || header.jwk || header.x5u) throw new Error('Upstream token nominates its own key');

  const keySet = await fetch(expected.jwksUri, { signal: AbortSignal.timeout(5000) }).then((r) => r.json());
  const jwk = keySet.keys?.find((key: { kid?: string }) => key.kid === header.kid);
  if (!jwk) throw new Error('Upstream token names an unknown key');

  const { createPublicKey, verify: cryptoVerify } = await import('crypto');
  const ok = cryptoVerify(
    'sha256',
    Buffer.from(`${rawHeader}.${rawPayload}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(rawSignature, 'base64url'),
  );
  if (!ok) throw new Error('Upstream token signature did not verify');

  const claims = JSON.parse(Buffer.from(rawPayload, 'base64url').toString()) as Record<string, unknown>;
  if (claims.iss !== expected.issuer) throw new Error('Upstream token is from another issuer');

  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(expected.audience)) throw new Error('Upstream token was not issued for us');

  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp === 'number' && claims.exp + 60 < now) throw new Error('Upstream token has expired');

  // The nonce ties the token to the request we started. Without it an id token obtained elsewhere
  // for the same client can be replayed into this callback.
  if (expected.nonce) {
    const presented = String(claims.nonce ?? '');
    const a = Buffer.from(presented);
    const b = Buffer.from(expected.nonce);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error('Upstream token nonce does not match');
  }

  return claims;
}

export const oidcIdentityProvider: IdentityProviderAdapter = {
  name: 'oidc',
  protocol: 'oidc',

  async authorizationUrl(providerId, state) {
    const provider = await load(providerId);
    const where = await endpoints(provider);
    const url = new URL(where.authorization);
    url.searchParams.set('client_id', provider.config.clientId ?? '');
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', (provider.config.scopes ?? ['openid', 'profile', 'email']).join(' '));
    url.searchParams.set('state', state);
    // Derived from the state rather than stored beside it: one value to carry, and the two cannot
    // drift apart or be mismatched by a lost record.
    url.searchParams.set('nonce', createHash('sha256').update(`nonce:${state}`).digest('base64url'));
    url.searchParams.set('redirect_uri', String(provider.config.redirectUri ?? ''));
    return url.toString();
  },

  async exchange(providerId, payload) {
    const provider = await load(providerId);
    const where = await endpoints(provider);
    const code = String(payload.code ?? '');
    const state = String(payload.state ?? '');
    if (!code) throw new Error('No authorization code returned');

    const response = await fetch(where.token, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: String(provider.config.redirectUri ?? ''),
        client_id: provider.config.clientId ?? '',
        // The secret is read from configuration by reference, so the record can be shown to an
        // operator without showing them a credential.
        client_secret: process.env[provider.config.clientSecretRef ?? ''] ?? '',
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) throw new Error(`Upstream token exchange failed for ${provider.name}`);

    const tokens = await response.json();
    if (!tokens.id_token) throw new Error('Upstream returned no id token');

    return verifyUpstream(tokens.id_token, {
      issuer: where.issuer,
      audience: provider.config.clientId ?? '',
      jwksUri: where.jwks,
      nonce: state ? createHash('sha256').update(`nonce:${state}`).digest('base64url') : undefined,
    });
  },
};
