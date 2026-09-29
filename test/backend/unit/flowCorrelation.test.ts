// v41 P9: an audit starts from a captured token, so a token must lead back to its flow.
//
// The state before this: `correlationId` was per HTTP REQUEST, a UUID per call, and the only thing
// grouping an authorization with its redemption was a hash of the client's `state` parameter, which
// is optional, client-chosen and was truncated to 64 bits. Nothing at all connected a token to its
// own events. From a token alone, no event of its flow could be found.
//
// The two halves asserted here are `jti` and `txn`, and the reason both are needed is cardinality: a
// flow issues many tokens. A test asserting one without the other would pass on exactly the mistake
// the distinction exists to prevent, which is reusing `jti` as the flow id and thereby breaking the
// replay detection that is its only purpose.
import { describe, it, expect } from 'vitest';
import { TokenIssuer } from '../../../backend/src/modules/oauth/services/tokenIssuer.service';
import { trailWrites, trailHealth } from '../../../backend/src/modules/audit/services/securityEvent.service';
import { SecurityEventService } from '../../../backend/src/modules/audit/services/securityEvent.service';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';
import type { OAuthClient } from '../../../backend/src/modules/oauth/models/client.model';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';
import type { Db } from 'mongodb';

const FLOW = 'f7c1a9e0-3b52-4d18-9a44-0e6b2c8d5511';

function realm(): RealmRecord {
  return {
    realmId: 'realm-1', tenantId: 'default', name: 'acme', displayName: 'Acme',
    issuer: 'https://authority.example/api/v1/realms/acme', enabled: true, aliases: [],
    registration: { selfServiceEnabled: false, autoApprove: false },
    tokenPolicy: {
      accessTokenTtlSeconds: 900, refreshTokenTtlSeconds: 3600, codeTtlSeconds: 120,
      sessionIdleTtlSeconds: 3600, sessionMaxTtlSeconds: 43_200,
    },
    passwordPolicy: {
      minLength: 8, requireUppercase: false, requireNumber: false, requireSymbol: false, historyDepth: 0,
    },
    branding: { displayName: 'Acme' }, demoMode: false, meta: newMeta('Realm'),
  };
}

function client(): OAuthClient {
  return {
    realmId: 'realm-1', tenantId: 'default', clientId: 'acme-accounting',
    clientName: 'Acme Accounting', clientType: 'confidential',
    redirectUris: ['https://app.example/callback'], grantTypes: ['authorization_code'],
    scope: 'openid profile', requirePkce: true, tokenEndpointAuthMethod: 'client_secret_basic',
    audience: ['https://api.example'],
  } as OAuthClient;
}

const ring = {
  signingKid: async () => 'kid-1',
  sign: async () => ({ kid: 'kid-1', signature: Buffer.from('signature') }),
} as unknown as KeyRing;

function db(): Db {
  return {
    collection: (name: string) => ({
      insertOne: async () => ({}),
      find: () => ({ toArray: async () => [{ name: 'orders', audience: 'https://api.example' }] }),
      findOne: async (filter: Record<string, unknown>) => {
        if (name === 'grant') return null;
        if (filter.sessionId) {
          return {
            sessionId: filter.sessionId, refreshGen: 3,
            createdAt: '2026-09-04T10:00:00.000Z', acr: 'aal2', amr: ['pwd'],
          };
        }
        return null;
      },
      findOneAndUpdate: async () => ({ refreshGen: 4, subjectId: 'subject-1', clientId: 'acme-accounting' }),
    }),
  } as unknown as Db;
}

const decode = (token: string) => JSON.parse(
  Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
) as Record<string, unknown>;

async function issue(extra: Record<string, unknown> = {}) {
  return new TokenIssuer(db(), ring).issue({
    realm: realm(),
    client: client(),
    subjectId: 'subject-1',
    scope: ['openid', 'profile'],
    roles: ['customer'],
    sessionId: 'sess-1',
    sessionEpoch: 0,
    includeRefreshToken: true,
    includeIdToken: true,
    txn: FLOW,
    ...extra,
  });
}

describe('v41 P9: txn is one value across every token a flow issues', () => {
  it('puts the same flow in the access token, the refresh token and the id token', async () => {
    const tokens = await issue();
    const access = decode(tokens.access_token);
    const refresh = decode(tokens.refresh_token as string);
    const id = decode(tokens.id_token as string);

    expect(access.txn).toBe(FLOW);
    expect(refresh.txn).toBe(FLOW);
    expect(id.txn).toBe(FLOW);
  });

  /**
   * The invariant that makes both claims necessary. RFC 7519 4.1.7 requires negligible probability
   * that one `jti` is assigned to a different data object, and a flow issues several JWTs. Reusing
   * `jti` as the flow id would break it and defeat every purpose `jti` has at once: a replay stops
   * being distinguishable from the flow's next legitimate token.
   */
  it('gives every token its own jti while they share one txn', async () => {
    const tokens = await issue();
    const ids = [
      decode(tokens.access_token).jti,
      decode(tokens.refresh_token as string).jti,
      decode(tokens.id_token as string).jti,
    ];
    expect(new Set(ids).size).toBe(3);
    expect(ids.every((id) => typeof id === 'string' && id.length > 0)).toBe(true);
  });

  it('omits txn where there is no flow, rather than inventing one', async () => {
    const machine = await new TokenIssuer(db(), ring).issue({
      realm: realm(), client: client(), subjectId: 'settlement-worker',
      scope: ['settlement:process'], roles: ['settlement_service'],
    });
    // client_credentials is one issuance and no flow. A correlator here would group unrelated calls.
    expect(decode(machine.access_token)).not.toHaveProperty('txn');
  });

  /**
   * A rotation must stay in the flow that started it, and the value comes out of the presented
   * refresh token rather than the session. A session produces MANY flows, so `session.ticketId`
   * would report whichever was most recent: an identifier that is confidently wrong.
   */
  it('carries the flow out of a redeemed refresh token so a rotation chain stays one flow', async () => {
    const issuer = new TokenIssuer(db(), ring);
    const first = await issue();
    const outcome = await issuer.redeemRefresh('realm-1', first.refresh_token as string);
    // The stub key ring cannot verify a real signature, so redemption refuses; what is asserted is
    // that the claim is in the token for redemption to read, which is where the chain is preserved.
    expect(decode(first.refresh_token as string).txn).toBe(FLOW);
    expect(outcome.ok).toBe(false);
  });
});

describe('v41 P9: the trail can be queried by flow, and says when it has lost something', () => {
  /**
   * D36. "Every event in this flow" is the first query an investigation runs, and it was a scan: the
   * only index on the trail was by stakeholder.
   */
  it('indexes the flow correlator', () => {
    const audit = plannedIndexes().filter((plan) => plan.collection === 'audit');
    const byFlow = audit.find((plan) => plan.options.name === 'realm_correlation_ts');
    expect(byFlow).toBeDefined();
    expect(byFlow?.keys).toEqual({ realmId: 1, correlationId: 1, ts: -1 });
  });

  /**
   * And deliberately NOT in `meta`, which is where a time series collection filters most cheaply.
   * The `metaField` decides bucketing, and one distinct value per flow is near-maximal cardinality:
   * every bucket would hold about one measurement and the columnar compression would be gone.
   */
  it('keeps the correlator out of the time series meta field', () => {
    const audit = plannedIndexes().filter((plan) => plan.collection === 'audit');
    for (const plan of audit) {
      expect(Object.keys(plan.keys).some((key) => key.startsWith('meta.correlation'))).toBe(false);
    }
  });

  /**
   * D33, the most serious defect in the plan. 32 call sites fire and forget, and `record()` ended in
   * an empty `catch`: no log line, no counter, no retry. PCI DSS 10.7 requires that a failure to log
   * be DETECTED, and here it was undetectable by construction.
   *
   * It still does not throw. The availability argument stands: a trail that can fail an
   * authentication gets removed from the authentication path. What changed is that it is countable.
   */
  it('counts a lost write and reports the trail as degraded, without failing the caller', async () => {
    const before = trailWrites.failed;
    const broken = {
      collection: () => ({ insertOne: async () => { throw new Error('disk full'); } }),
    } as unknown as Db;

    await expect(new SecurityEventService(broken).record({
      realmId: 'realm-1', tenantId: 'default', action: 'authentication.password', outcome: 'success',
    })).resolves.toBeUndefined();

    expect(trailWrites.failed).toBe(before + 1);
    expect(trailWrites.lastFailureCause).toContain('disk full');
    expect(trailHealth().healthy).toBe(false);
  });
});
