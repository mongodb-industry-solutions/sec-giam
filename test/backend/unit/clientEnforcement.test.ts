// Client registration enforcement, strict and soft.
//
// The interesting half of this suite is not that soft mode admits an unregistered client. It is
// everything soft mode still refuses, and how little the admitted client gets. A "soft" mode that
// quietly became "skip verification" would pass a test that only checked admission, so every case
// below is either a refusal that survives soft mode or a piece of authority that does not.
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as bcrypt from 'bcryptjs';
import {
  ClientAuthService, provisionalClient, SOFT_ADMISSION_SCOPE,
} from '../../../backend/src/modules/oauth/services/clientAuth.service';
import { TokenIssuer } from '../../../backend/src/modules/oauth/services/tokenIssuer.service';
import { enforcementFor } from '../../../backend/src/modules/realm/models/realm.model';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';
import type { ClientRecord } from '../../../backend/src/modules/oauth/models/client.model';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import { config } from '../../../backend/src/config';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';
import type { Db } from 'mongodb';

const KNOWN_SECRET = 'the-registered-secret';

function realmOf(mode?: RealmRecord['clientEnforcement']): RealmRecord {
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
    ...(mode ? { clientEnforcement: mode } : {}),
    meta: newMeta('Realm'),
  };
}

async function registeredClient(overrides: Partial<ClientRecord> = {}): Promise<ClientRecord> {
  return {
    realmId: 'realm-1',
    tenantId: 'default',
    clientId: 'orders-web',
    clientSecretHash: await bcrypt.hash(KNOWN_SECRET, 4),
    clientName: 'Orders',
    clientType: 'confidential',
    redirectUris: ['https://app.example/callback'],
    grantTypes: ['client_credentials'],
    scope: 'openid read:orders write:orders',
    requirePkce: false,
    tokenEndpointAuthMethod: 'client_secret_basic',
    status: 'active',
    meta: newMeta('Client'),
    ...overrides,
  };
}

/** A directory holding exactly the clients handed to it, and nothing else. */
function dbOf(clients: ClientRecord[]): Db {
  return {
    collection: () => ({
      findOne: async (filter: { clientId: string }) =>
        clients.find((client) => client.clientId === filter.clientId) ?? null,
    }),
  } as unknown as Db;
}

describe('client enforcement: the mode in force is per realm, defaulting to strict', () => {
  it('defaults to strict when nothing is configured anywhere', () => {
    expect(config.app.clientEnforcement).toBe('strict');
    expect(enforcementFor(realmOf())).toBe('strict');
  });

  it('lets a realm state its own mode without changing the ones beside it', () => {
    // Onboarding is something ONE realm goes through while its neighbours are established, which a
    // single process-wide switch could not express.
    expect(enforcementFor(realmOf('soft'))).toBe('soft');
    expect(enforcementFor(realmOf('strict'))).toBe('strict');
    expect(enforcementFor(realmOf())).toBe(config.app.clientEnforcement);
  });
});

describe('client enforcement: strict refuses an unregistered client, exactly as before', () => {
  it('refuses a client it has never seen', async () => {
    const outcome = await new ClientAuthService(dbOf([])).authenticate(
      realmOf('strict'),
      { clientId: 'a-stranger', clientSecret: 'anything' },
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    expect(outcome).toEqual({ error: 'invalid_client', description: 'unknown client' });
  });

  it('admits a registered client with the right secret, with its full authority', async () => {
    const client = await registeredClient();
    const outcome = await new ClientAuthService(dbOf([client])).authenticate(
      realmOf('strict'),
      { clientId: 'orders-web', clientSecret: KNOWN_SECRET },
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    expect(outcome).toMatchObject({ softAdmitted: false });
    expect('client' in outcome && outcome.client.scope).toBe('openid read:orders write:orders');
  });
});

describe('client enforcement: soft admits, marks and limits', () => {
  it('admits a client that has never registered, and says so', async () => {
    const outcome = await new ClientAuthService(dbOf([])).authenticate(
      realmOf('soft'),
      { clientId: 'a-stranger', clientSecret: 'whatever-it-brought' },
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    // Marked, not merely let through. The flag is what every reduction downstream keys off.
    expect(outcome).toMatchObject({ softAdmitted: true });
    expect('client' in outcome && outcome.client.clientId).toBe('a-stranger');
  });

  it('gives a soft admission the minimum scope and none of the privileged grants', () => {
    const provisional = provisionalClient(realmOf('soft'), 'a-stranger');
    expect(provisional.scope).toBe(SOFT_ADMISSION_SCOPE);
    expect(provisional.scope).toBe('openid');
    expect(provisional.grantTypes).toEqual(['authorization_code', 'client_credentials']);
    // Decoupled authentication and token exchange are not onboarding problems, so they stay shut.
    expect(provisional.grantTypes).not.toContain('urn:openid:params:grant-type:ciba');
    expect(provisional.grantTypes).not.toContain('urn:ietf:params:oauth:grant-type:token-exchange');
    // Never written. A persisted provisional record would be self-service registration.
    expect(provisional.clientSecretHash).toBeUndefined();
  });

  it('offers no soft admission where the caller did not ask for it', async () => {
    // Introspection and decoupled authentication pass allowSoftAdmission: false, so a soft realm
    // changes nothing about them.
    const outcome = await new ClientAuthService(dbOf([])).authenticate(
      realmOf('soft'),
      { clientId: 'a-stranger', clientSecret: 'anything' },
      { requireAuthentication: true, allowSoftAdmission: false },
    );
    expect(outcome).toEqual({ error: 'invalid_client', description: 'unknown client' });
  });
});

describe('client enforcement: soft relaxes NOT BEING REGISTERED, and nothing else', () => {
  it('still refuses a wrong secret on a client it knows', async () => {
    // The case that decides whether this is an onboarding ramp or a hole. The client is registered,
    // so being unregistered is not its problem, and soft mode has nothing to say about it.
    const client = await registeredClient();
    const outcome = await new ClientAuthService(dbOf([client])).authenticate(
      realmOf('soft'),
      { clientId: 'orders-web', clientSecret: 'not-the-registered-secret' },
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    expect(outcome).toEqual({ error: 'invalid_client', description: 'invalid client_secret' });
  });

  it('still refuses a confidential client that presents no secret at all', async () => {
    const client = await registeredClient();
    const outcome = await new ClientAuthService(dbOf([client])).authenticate(
      realmOf('soft'),
      { clientId: 'orders-web' },
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    expect(outcome).toEqual({ error: 'invalid_client', description: 'client authentication required' });
  });

  it('still refuses a revoked client, and a suspended one', async () => {
    for (const status of ['revoked', 'suspended'] as const) {
      const client = await registeredClient({ status });
      // eslint-disable-next-line no-await-in-loop
      const outcome = await new ClientAuthService(dbOf([client])).authenticate(
        realmOf('soft'),
        { clientId: 'orders-web', clientSecret: KNOWN_SECRET },
        { requireAuthentication: true, allowSoftAdmission: true },
      );
      // Not "unknown client": a revoked client is a decision somebody took, and soft mode does not
      // reverse it by admitting the same caller as a stranger instead.
      expect(outcome).toEqual({ error: 'invalid_client', description: 'client is not active' });
    }
  });

  it('still requires a client_id', async () => {
    const outcome = await new ClientAuthService(dbOf([])).authenticate(
      realmOf('soft'),
      {},
      { requireAuthentication: true, allowSoftAdmission: true },
    );
    expect(outcome).toEqual({ error: 'invalid_client', description: 'client_id is required' });
  });

  it('still refuses a grant the soft admission does not hold', async () => {
    const auth = new ClientAuthService(dbOf([]));
    const provisional = provisionalClient(realmOf('soft'), 'a-stranger');
    expect(auth.allowsGrant(provisional, 'client_credentials')).toBe(true);
    expect(auth.allowsGrant(provisional, 'urn:openid:params:grant-type:ciba')).toBe(false);
  });
});

describe('client enforcement: a soft-admitted token genuinely carries less authority', () => {
  const claimsOf = (token: string) => JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
  ) as Record<string, unknown>;

  const ring = {
    signingKid: async () => 'kid-1',
    sign: async () => ({ kid: 'kid-1', signature: Buffer.from('signature') }),
  } as unknown as KeyRing;

  const issuingDb = (): Db => ({
    collection: () => ({
      insertOne: async () => ({}),
      find: () => ({ toArray: async () => [{ name: 'orders', audience: 'orders' }] }),
      // Role holdings live on the principal now, so issuance reads the subject rather than a
      // separate assignment collection. No holdings here: this suite is about what registration
      // buys, not about what a role grants.
      findOne: async () => null,
    }),
  } as unknown as Db);

  const input = async () => ({
    realm: realmOf('soft'),
    client: await registeredClient(),
    subjectId: 'subject-1',
    scope: ['openid', 'read:orders', 'write:orders'],
    permissions: [{ resource: 'orders', action: 'view' }],
    roles: ['operator'],
    accountHolderRef: 'holder-1',
    includeRefreshToken: true,
  });

  it('issues the full authority when the client is registered', async () => {
    const full = await new TokenIssuer(issuingDb(), ring).issue(await input());
    const claims = claimsOf(full.access_token);
    expect(claims.permissions).toEqual([{ resource: 'orders', action: 'view' }]);
    expect(claims.roles).toEqual(['operator']);
    expect(full.scope).toBe('openid read:orders write:orders');
    expect(full.refresh_token).toBeTruthy();
  });

  it('strips the permissions, the roles, the refresh token and the scope when it is not', async () => {
    // Same input, one flag different. If registration bought nothing, nobody would ever complete it.
    const reduced = await new TokenIssuer(issuingDb(), ring, { reducedAuthority: true })
      .issue(await input());
    const claims = claimsOf(reduced.access_token);

    expect(claims.permissions).toBeUndefined();
    expect(claims.roles).toBeUndefined();
    // No binding to the subject's own records either: that is authority too.
    expect(claims.account_holder).toBeUndefined();
    expect(claims.scope).toBe('openid');
    expect(reduced.scope).toBe('openid');
    // A refresh token would let the reduced admission outlive the onboarding it was granted for.
    expect(reduced.refresh_token).toBeUndefined();
  });

  it('still identifies who it is, so the trail is not anonymous', async () => {
    const reduced = await new TokenIssuer(issuingDb(), ring, { reducedAuthority: true })
      .issue(await input());
    const claims = claimsOf(reduced.access_token);
    // Reduced is not unattributable. The whole point of admitting it is knowing who to chase.
    expect(claims.sub).toBe('subject-1');
    expect(claims.client_id).toBe('orders-web');
    expect(claims.iss).toBe('https://authority.example/realms/acme');
  });
});
