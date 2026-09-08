// v41 P1: the claim contract, asserted claim by claim.
//
// The point of this suite is what a token must NOT carry as much as what it must. A test that only
// checks the presence of the claims it knows about passes unchanged after somebody adds a private
// claim nobody agreed to, or leaves a renamed one in place beside its replacement. So the shapes
// below are asserted exactly: an unexpected key fails, and so does a missing one.
//
// The reference payloads in tmp/dev.v41.plan.md section 4 are the source. When one changes, both
// change, and the plan says which.
import { describe, it, expect } from 'vitest';
import * as bcrypt from 'bcryptjs';
import { TokenIssuer, MAX_ACCESS_TOKEN_CLAIMS_BYTES } from '../../../backend/src/modules/oauth/services/tokenIssuer.service';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';
import type { OAuthClient } from '../../../backend/src/modules/oauth/models/client.model';
import { clientMetadata } from '../../../backend/src/modules/oauth/models/client.model';
import type { CredentialRecord } from '../../../backend/src/modules/directory/models/credential.model';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import { amrFor } from '../../../backend/src/modules/authentication/models/authenticationContext';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';
import type { Db } from 'mongodb';

const SESSION_CREATED_AT = '2026-09-04T10:00:00.000Z';

function realm(): RealmRecord {
  return {
    realmId: 'realm-1',
    tenantId: 'default',
    name: 'acme',
    displayName: 'Acme',
    issuer: 'https://authority.example/realms/acme',
    enabled: true,
    aliases: [],
    registration: { selfServiceEnabled: false, autoApprove: false },
    tokenPolicy: {
      accessTokenTtlSeconds: 900,
      refreshTokenTtlSeconds: 3600,
      codeTtlSeconds: 120,
      sessionIdleTtlSeconds: 3600,
      sessionMaxTtlSeconds: 43_200,
    },
    passwordPolicy: {
      minLength: 8, requireUppercase: false, requireNumber: false, requireSymbol: false, historyDepth: 0,
    },
    branding: { displayName: 'Acme' },
    demoMode: false,
    meta: newMeta('Realm'),
  };
}

async function client(overrides: Partial<OAuthClient> = {}): Promise<CredentialRecord> {
  const flat: Partial<OAuthClient> = {
    clientId: 'orders-web',
    clientName: 'Orders',
    clientType: 'confidential',
    redirectUris: ['https://app.example/callback'],
    grantTypes: ['authorization_code'],
    scope: 'openid profile',
    requirePkce: true,
    tokenEndpointAuthMethod: 'client_secret_basic',
    ...overrides,
  };
  return {
    realmId: 'realm-1',
    tenantId: 'default',
    credentialId: 'cred-1',
    subjectId: flat.clientId as string,
    type: 'oauth_client',
    ownerId: 'subject-1',
    clientId: flat.clientId as string,
    hash: await bcrypt.hash('secret', 4),
    metadata: clientMetadata(flat),
    status: 'active',
    assurance: { level: 'aal1', method: 'client_secret' },
    createdAt: '2026-01-01T00:00:00.000Z',
    meta: newMeta('Credential'),
  };
}

const ring = {
  signingKid: async () => 'kid-1',
  sign: async () => ({ kid: 'kid-1', signature: Buffer.from('signature') }),
} as unknown as KeyRing;

/**
 * A database that answers the two reads issuance makes, and nothing more.
 *
 * `session` carries the authentication context, because that is where it is resolved at sign-in and
 * it is what the `auth_time`, `acr` and `amr` claims are built from.
 */
function issuingDb(session: Record<string, unknown> | null = {
  sessionId: 'sess-1', refreshGen: 0, createdAt: SESSION_CREATED_AT, acr: 'aal2', amr: ['pwd', 'otp'],
}): Db {
  return {
    collection: () => ({
      insertOne: async () => ({}),
      find: () => ({ toArray: async () => [{ name: 'orders', audience: 'https://api.example' }] }),
      findOne: async (filter: Record<string, unknown>) => (filter.sessionId ? session : null),
    }),
  } as unknown as Db;
}

const decode = (token: string) => JSON.parse(
  Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
) as Record<string, unknown>;

const header = (token: string) => JSON.parse(
  Buffer.from(token.split('.')[0], 'base64url').toString('utf8'),
) as Record<string, unknown>;

async function personTokens(extra: Record<string, unknown> = {}, session?: Record<string, unknown> | null) {
  return new TokenIssuer(issuingDb(session), ring).issue({
    realm: realm(),
    client: await client() as unknown as OAuthClient,
    subjectId: 'subject-1',
    scope: ['openid', 'profile'],
    roles: ['fraud_analyst'],
    permissions: ['transaction:read', 'case:read'],
    sessionId: 'sess-1',
    sessionEpoch: 0,
    accountHolderRef: 'holder-1',
    includeRefreshToken: true,
    includeIdToken: true,
    ...extra,
  });
}

describe('v41 P1: the access token carries exactly the contracted claims', () => {
  it('carries every required claim and no unexpected one, for a person with roles only', async () => {
    const claims = decode((await personTokens()).access_token);

    expect(new Set(Object.keys(claims))).toEqual(new Set([
      'iss', 'aud', 'sub', 'jti', 'iat', 'exp',
      'scope', 'client_id',
      'auth_time', 'acr', 'amr',
      'sid', 'session_epoch',
      'roles', 'account_holder',
    ]));

    expect(claims.iss).toBe('https://authority.example/realms/acme');
    expect(claims.aud).toEqual(['https://api.example']);
    expect(claims.sub).toBe('subject-1');
    expect(claims.scope).toBe('openid profile');
    expect(claims.client_id).toBe('orders-web');
    expect(claims.roles).toEqual(['fraud_analyst']);
  });

  it('stamps the RFC 9068 header type, so an id token cannot be presented as an access token', async () => {
    expect(header((await personTokens()).access_token).typ).toBe('at+jwt');
  });

  /**
   * D42. `nbf` was emitted equal to `iat`, which is 22 bytes carrying nothing a verifier can act on.
   * Asserted as absent rather than merely not asserted, so re-adding it fails here.
   */
  it('emits no `nbf`, because it duplicated `iat` exactly', async () => {
    expect(decode((await personTokens()).access_token)).not.toHaveProperty('nbf');
  });

  /**
   * D9. The claim is `entitlements`, per RFC 9068 2.2.3.1. The pre-rename name must not survive
   * beside it: two names for one claim is how a resource server ends up reading the stale one.
   */
  it('names the fine-grained claim `entitlements`, and never `permissions`', async () => {
    const narrowed = decode((await personTokens({ requestedPermissions: ['transaction:read'] })).access_token);
    expect(narrowed.entitlements).toEqual(['transaction:read']);
    expect(narrowed).not.toHaveProperty('permissions');
  });

  it('omits entitlements entirely when the client did not narrow, because roles are the default', async () => {
    const claims = decode((await personTokens()).access_token);
    expect(claims).not.toHaveProperty('entitlements');
    expect(claims.roles).toEqual(['fraud_analyst']);
  });

  /**
   * D11. Step-up is impossible without these three, and the sources already existed: the assurance
   * level the method achieved, and the method that achieved it.
   */
  it('carries the authentication context resolved at sign-in', async () => {
    const claims = decode((await personTokens()).access_token);
    expect(claims.auth_time).toBe(Math.floor(Date.parse(SESSION_CREATED_AT) / 1000));
    expect(claims.acr).toBe('aal2');
    expect(claims.amr).toEqual(['pwd', 'otp']);
  });

  it('omits the authentication context when there is no session to have authenticated in', async () => {
    const machine = await new TokenIssuer(issuingDb(null), ring).issue({
      realm: realm(),
      client: await client({ grantTypes: ['client_credentials'] }) as unknown as OAuthClient,
      subjectId: 'settlement-worker',
      scope: ['settlement:process'],
      roles: ['settlement_service'],
    });
    const claims = decode(machine.access_token);

    // client_credentials creates no session, so there is no authentication event to describe. The
    // absence is the correct answer rather than a gap.
    for (const claim of ['auth_time', 'acr', 'amr', 'sid', 'session_epoch']) {
      expect(claims, claim).not.toHaveProperty(claim);
    }
    expect(machine.refresh_token).toBeUndefined();
  });

  /**
   * The invariant that holds across every case: a claim is absent, never empty. `roles: []` would
   * force every resource server to distinguish "none" from "present but empty".
   */
  it('never emits an empty array or an empty string as a claim', async () => {
    const claims = decode((await personTokens({ roles: [], permissions: [] })).access_token);
    for (const [name, value] of Object.entries(claims)) {
      if (Array.isArray(value)) expect(value.length, name).toBeGreaterThan(0);
      if (typeof value === 'string') expect(value.length, name).toBeGreaterThan(0);
    }
    expect(claims).not.toHaveProperty('roles');
  });
});

describe('v41 P1: the refresh token and the id token', () => {
  it('stamps the refresh token with its own type, not the generic JWT', async () => {
    // D13. The argument that justifies `at+jwt` applies here: a distinct type is what stops one kind
    // of token this authority signed being presented as another.
    expect(header((await personTokens()).refresh_token as string).typ).toBe('rt+jwt');
  });

  it('carries only what redemption needs in the refresh token', async () => {
    const claims = decode((await personTokens()).refresh_token as string);
    expect(new Set(Object.keys(claims))).toEqual(new Set([
      'iss', 'aud', 'sub', 'sid', 'gen', 'client_id', 'jti', 'iat', 'exp',
    ]));
    // Addressed to the issuer itself: redeemed here, accepted nowhere else.
    expect(claims.aud).toBe('https://authority.example/realms/acme');
  });

  /**
   * D43. OIDC Core 5.4: the claims the `profile`, `email`, `address` and `phone` scopes request are
   * returned from the UserInfo endpoint when an access token is issued, which in the code flow is
   * always. They were also emitted here without checking the `profile` scope at all.
   */
  it('puts no profile claims in the id token, because userinfo serves them', async () => {
    const claims = decode((await personTokens()).id_token as string);
    for (const claim of ['name', 'preferred_username', 'email', 'email_verified']) {
      expect(claims, claim).not.toHaveProperty(claim);
    }
    // The authentication context does belong here: an RP checks it without introspecting.
    expect(claims.acr).toBe('aal2');
    expect(claims.aud).toBe('orders-web');
  });
});

describe('v41 P1: the size budget is enforced at issuance', () => {
  it('refuses a claim set over the budget rather than letting a proxy cut it', async () => {
    /**
     * 120 expanded entitlements, which is past the measured threshold of 84 for a 2 KB claim set.
     *
     * The plan first claimed sixty would breach it, and that was an arithmetic error: sixty is 1574
     * bytes of claims, comfortably inside the budget. The number is measured here rather than
     * asserted from memory, because a budget test that never fires is worse than none.
     */
    const many = Array.from({ length: 120 }, (_, i) => `resource${i}:action`);
    await expect(personTokens({ permissions: many, requestedPermissions: many }))
      .rejects.toThrow(/over the 2048 byte budget/);
  });

  it('leaves headroom on the largest legitimate shape', async () => {
    const delegated = await personTokens({
      actor: { sub: 'agent-3f21', client_id: 'orders-web', act: { sub: 'orchestrator-01' } },
      requestedPermissions: ['transaction:read'],
    });
    const size = Buffer.byteLength(JSON.stringify(decode(delegated.access_token)), 'utf8');
    expect(size).toBeLessThan(MAX_ACCESS_TOKEN_CLAIMS_BYTES);
  });
});

describe('v41 P1: amr values come from RFC 8176 and not from the method name', () => {
  it('maps each implemented method to its registered value', () => {
    expect(amrFor('password')).toEqual(['pwd']);
    expect(amrFor('public_key')).toEqual(['swk']);
    expect(amrFor('totp')).toEqual(['otp']);
    expect(amrFor('client_secret')).toEqual(['pwd']);
  });

  it('appends mfa when more than one factor was involved, so an RP need not know the combinations', () => {
    expect(amrFor('password', 'totp')).toEqual(['pwd', 'otp', 'mfa']);
  });

  it('reports nothing for a method it has no registered value for, rather than inventing one', () => {
    // An unmapped method must not leak its internal name into a standard claim.
    expect(amrFor('some_future_method')).toEqual([]);
    expect(amrFor(undefined)).toEqual([]);
  });
});
