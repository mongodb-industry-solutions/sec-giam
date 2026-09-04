// v41 P3: the consent a token was issued under, and the constraints it carries.
//
// Before this, `grant.constraints` reached no resource server under EITHER verification model. A
// token limited to a value ceiling was indistinguishable from one with no limit, so the centralised
// model was not merely unused, it was impossible: nothing in a token led back to the grant.
//
// Two things are asserted, and the second is the one that would fail silently. That `grant_id` is
// present when a grant exists is easy to see. That it is ABSENT when none does is what tells a
// resource server there is nothing to introspect, and a test that only checked presence would pass
// on an authority that emitted a stale grant for everybody.
import { describe, it, expect } from 'vitest';
import { TokenIssuer, InvalidTargetError } from '../../../backend/src/modules/oauth/services/tokenIssuer.service';
import {
  authorizationDetailsFor, hasConstraints, DEFAULT_AUTHORIZATION_DETAIL_TYPE,
} from '../../../backend/src/modules/oauth/services/authorizationDetails';
import type { GrantRecord } from '../../../backend/src/modules/consent/models/grant.model';
import type { RealmRecord } from '../../../backend/src/modules/realm/models/realm.model';
import type { OAuthClient } from '../../../backend/src/modules/oauth/models/client.model';
import { newMeta } from '../../../backend/src/shared/models/base.model';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';
import type { Db } from 'mongodb';

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
      accessTokenTtlSeconds: 900, refreshTokenTtlSeconds: 3600, codeTtlSeconds: 120,
      sessionIdleTtlSeconds: 3600, sessionMaxTtlSeconds: 43_200,
    },
    passwordPolicy: {
      minLength: 8, requireUppercase: false, requireNumber: false, requireSymbol: false, historyDepth: 0,
    },
    branding: { displayName: 'Acme' },
    demoMode: false,
    meta: newMeta('Realm'),
  };
}

/**
 * The FLAT client, as the issuer actually receives it.
 *
 * Deliberately not a `CredentialRecord` cast to an `OAuthClient`, which is what the older suites
 * here do. The cast is why this test first failed: `audience` lives under `metadata` on the stored
 * credential, so a cast client declares none and the issuer falls through to the realm-wide
 * audience. The production path projects the credential into this shape before issuing, so
 * building the projected shape is what exercises the real contract.
 */
function client(overrides: Partial<OAuthClient> = {}): OAuthClient {
  return {
    realmId: 'realm-1',
    tenantId: 'default',
    clientId: 'acme-accounting',
    clientName: 'Acme Accounting',
    clientType: 'confidential',
    redirectUris: ['https://app.example/callback'],
    grantTypes: ['authorization_code'],
    scope: 'openid payments:write',
    requirePkce: true,
    tokenEndpointAuthMethod: 'client_secret_basic',
    audience: ['https://api.example', 'https://bank.example'],
    ...overrides,
  } as OAuthClient;
}

const ring = {
  signingKid: async () => 'kid-1',
  sign: async () => ({ kid: 'kid-1', signature: Buffer.from('signature') }),
} as unknown as KeyRing;

const CONSTRAINED: Partial<GrantRecord> = {
  grantId: 'g-77b3d105',
  constraints: { maxValue: 500 },
  scope: 'openid payments:write',
  transactionId: 'tx-8812',
};

/**
 * A database that answers by collection name, so the grant read and the resource read can differ.
 *
 * `grant` is what P3 added: the issuer looks the record up itself rather than having it threaded
 * through six call sites, and this is where that read is exercised.
 */
function dbWith(options: {
  grant?: Partial<GrantRecord> | null;
  resources?: Array<{ name: string; audience: string; validationMode?: string }>;
} = {}): Db {
  const resources = options.resources ?? [{ name: 'orders', audience: 'https://api.example' }];
  return {
    collection: (name: string) => ({
      insertOne: async () => ({}),
      find: (filter: Record<string, unknown>) => ({
        toArray: async () => {
          if (name !== 'resource') return [];
          if (filter.validationMode) {
            return resources.filter((entry) => entry.validationMode === filter.validationMode);
          }
          return resources;
        },
      }),
      findOne: async (filter: Record<string, unknown>) => {
        if (name === 'grant') return options.grant ?? null;
        if (filter.sessionId) return { sessionId: filter.sessionId, refreshGen: 0, createdAt: '2026-09-04T10:00:00.000Z' };
        return null;
      },
    }),
  } as unknown as Db;
}

const decode = (token: string) => JSON.parse(
  Buffer.from(token.split('.')[1], 'base64url').toString('utf8'),
) as Record<string, unknown>;

async function issue(db: Db, extra: Record<string, unknown> = {}) {
  return new TokenIssuer(db, ring).issue({
    realm: realm(),
    client: client(),
    subjectId: 'subject-1',
    scope: ['openid', 'payments:write'],
    roles: ['customer'],
    ...extra,
  });
}

describe('v41 P3: grant_id is present when there is a grant, and absent when there is not', () => {
  it('carries the grant it was issued under', async () => {
    const claims = decode((await issue(dbWith({ grant: CONSTRAINED }))).access_token);
    expect(claims.grant_id).toBe('g-77b3d105');
  });

  /**
   * The half that would fail silently. No grant means nothing to introspect, and a resource server
   * relies on that: an authority that emitted a grant id regardless would send every caller to look
   * up a record that says nothing about this token.
   */
  it('omits it entirely when nobody consented', async () => {
    const claims = decode((await issue(dbWith({ grant: null }))).access_token);
    expect(claims).not.toHaveProperty('grant_id');
    expect(claims).not.toHaveProperty('authorization_details');
  });

  it('omits it for a soft admission, which must not point at an authorisation it is not exercising', async () => {
    const reduced = await new TokenIssuer(dbWith({ grant: CONSTRAINED }), ring, { reducedAuthority: true })
      .issue({
        realm: realm(),
        client: client(),
        subjectId: 'subject-1',
        scope: ['openid'],
        roles: ['customer'],
      });
    expect(decode(reduced.access_token)).not.toHaveProperty('grant_id');
  });
});

describe('v41 P3: the constraints travel, so local verification is not blind', () => {
  it('projects a value ceiling and a transaction binding into the claim', async () => {
    const claims = decode((await issue(dbWith({ grant: CONSTRAINED }))).access_token);
    expect(claims.authorization_details).toEqual([{
      type: DEFAULT_AUTHORIZATION_DETAIL_TYPE,
      actions: ['openid', 'payments:write'],
      maxValue: 500,
      transactionId: 'tx-8812',
    }]);
  });

  /**
   * The type is `urn:giam:constrained-grant` and never a business name. RFC 9396 2 leaves the
   * interpretation of `type` to the authorization server, which here means the deployment's resource
   * catalog. A built-in `payment_initiation` would put one industry's vocabulary inside an authority
   * that must serve several.
   */
  it('names no industry in the default type', () => {
    expect(DEFAULT_AUTHORIZATION_DETAIL_TYPE).toBe('urn:giam:constrained-grant');
    expect(DEFAULT_AUTHORIZATION_DETAIL_TYPE).not.toMatch(/payment|card|merchant|settlement|ledger/i);
  });

  it('emits nothing at all for a grant with no constraints, rather than an empty array', () => {
    const plain = { grantId: 'g-1', scope: 'openid', constraints: undefined } as unknown as GrantRecord;
    expect(hasConstraints(plain)).toBe(false);
    expect(authorizationDetailsFor(plain, ['https://api.example'])).toEqual([]);
  });

  /**
   * RFC 9396 9.1 recommends filtering to the specific audience. With a multi-valued `aud` that is
   * not cosmetic: a resource server must not receive a constraint addressed to another.
   */
  it('withholds a detail whose named resources this token does not address', () => {
    const elsewhere = {
      grantId: 'g-2',
      scope: 'payments:write',
      constraints: { maxValue: 500, allowedResources: ['https://other.example'] },
    } as unknown as GrantRecord;
    expect(authorizationDetailsFor(elsewhere, ['https://api.example'])).toEqual([]);
    // Addressed at the resource it names, it does travel.
    expect(authorizationDetailsFor(elsewhere, ['https://other.example'])[0].locations)
      .toEqual(['https://other.example']);
  });
});

describe('v41 P3: resource indicators narrow the audience, RFC 8707', () => {
  it('addresses the token at exactly what was asked for, within the registration', async () => {
    const claims = decode((await issue(dbWith(), { resources: ['https://api.example'] })).access_token);
    expect(claims.aud).toEqual(['https://api.example']);
  });

  it('addresses the whole registration when nothing was asked for', async () => {
    const claims = decode((await issue(dbWith())).access_token);
    expect(claims.aud).toEqual(['https://api.example', 'https://bank.example']);
  });

  /**
   * Refused, not dropped, and the asymmetry with a requested entitlement is deliberate. An
   * entitlement the subject lacks is dropped so that asking narrowly stays worth doing. An audience
   * the client cannot address means the client has the wrong idea of what it is talking to, and
   * handing back a token for a different API produces a 401 it cannot diagnose.
   */
  it('refuses a resource outside the registration with invalid_target', async () => {
    await expect(issue(dbWith(), { resources: ['https://not-registered.example'] }))
      .rejects.toThrow(InvalidTargetError);
  });
});

describe('v41 P3: a constrained grant reaching a locally verifying resource is recorded', () => {
  /**
   * `resource.validationMode` was registered, seeded and read by nothing. This is what it is for.
   *
   * The issuance is NOT refused: the resource server's choice stands, including one that puts it at
   * risk. What was unacceptable is that nobody could tell afterwards, so it becomes evidence.
   */
  it('issues the token and records that the constraints will not be re-checked', async () => {
    const recorded: Array<Record<string, unknown>> = [];
    const db = dbWith({
      grant: CONSTRAINED,
      resources: [{ name: 'orders', audience: 'https://api.example', validationMode: 'local-jwks' }],
    });
    const spied = {
      collection: (name: string) => {
        const inner = (db as unknown as { collection: (n: string) => Record<string, unknown> }).collection(name);
        if (name !== 'audit') return inner;
        return { ...inner, insertOne: async (doc: Record<string, unknown>) => { recorded.push(doc); return {}; } };
      },
    } as unknown as Db;

    const tokens = await issue(spied, {});
    expect(tokens.access_token).toBeTruthy();
    // Recorded asynchronously by design, so the trail cannot fail an issuance.
    await new Promise((done) => setTimeout(done, 0));
    expect(recorded.map((event) => event.action)).toContain('token.constraints_locally_enforced');
  });
});
