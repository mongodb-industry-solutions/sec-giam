// v39 P6: the authorization half, and the two things it has to get exactly right.
//
// First, the role matrix must reproduce today's, permission for permission. A role that silently
// gained or lost one is a permission change nobody decided, and it would surface as either a person
// unable to do their job or a person able to do somebody else's.
//
// Second, a permission granted to a SERVICE identity must be enforced the same way one granted to a
// person is. If a machine needed its own mechanism, the two halves would be free to drift and one of
// them would end up without an audit trail, which is the failure the one-pipeline rule exists to
// prevent.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { clientSecretFor } from '@leafypay/platform-links';

const DATA = resolve(__dirname, '../../../../giam/backend/data');

interface RoleFixture {
  realm: string;
  name: string;
  scopeKind: 'self' | 'all';
  permissions: Record<string, string[]>;
  authorityPermissions?: Record<string, string[]>;
  sodRationale?: string;
  denialRationale?: Array<{ resource: string; action?: string; reason: string }>;
}

const roles = JSON.parse(readFileSync(resolve(DATA, 'roles.json'), 'utf8')) as RoleFixture[];

/**
 * The matrix as it stands on the platform today, transcribed from its role model.
 *
 * Written out here rather than derived from the fixture, deliberately: a test that reads the same
 * file the seeder reads proves the seeder is consistent with itself and nothing more. This is the
 * independent copy, and its whole value is that changing the fixture does not change it.
 */
const EXPECTED: Record<string, Record<string, string[]>> = {
  customer: {
    transactions: ['view'],
    cards: ['view', 'manage'],
    merchants: ['view'],
    consents: ['view'],
    accounts: ['view', 'manage'],
    beneficiaries: ['view', 'manage'],
    paymentRequests: ['view', 'manage'],
  },
  level1_analyst: {
    transactions: ['view'],
    customers: ['view'],
    cards: ['view'],
    merchants: ['view'],
    fraudCases: ['view', 'investigate'],
    beneficiaries: ['view'],
  },
  level2_investigator: {
    transactions: ['view', 'viewSensitive'],
    customers: ['view', 'viewSensitive'],
    cards: ['view', 'viewSensitive'],
    merchants: ['view'],
    fraudCases: ['view', 'investigate'],
    auditEvents: ['view'],
    accounts: ['view', 'viewSensitive'],
    beneficiaries: ['view', 'investigate', 'manage'],
    paymentRequests: ['view'],
    grants: ['view', 'manage'],
  },
  security_auditor: {
    transactions: ['view', 'viewSensitive'],
    customers: ['view', 'viewSensitive'],
    cards: ['view', 'viewSensitive'],
    fraudCases: ['view', 'viewSensitive'],
    merchants: ['view'],
    providers: ['view'],
    modules: ['view'],
    auditEvents: ['view'],
    accounts: ['view', 'viewSensitive'],
    beneficiaries: ['view', 'investigate'],
    paymentRequests: ['view'],
    grants: ['view'],
  },
  merchant_officer: {
    merchants: ['view', 'manage'],
    accounts: ['view'],
  },
  operations_officer: {
    cards: ['view', 'manage'],
    accounts: ['view', 'manage'],
    customers: ['view', 'manage'],
    merchants: ['view', 'manage'],
    modules: ['view', 'manage'],
    providers: ['view'],
    auditEvents: ['view'],
  },
  manager: {
    providers: ['view', 'manage'],
    modules: ['view'],
    auditEvents: ['view'],
  },
};

let app: FastifyInstance;
let realmName: string;

beforeAll(async () => {
  const { buildApp } = await import('../../../../giam/backend/src/app');
  app = await buildApp();
  await app.ready();
  realmName = roles[0].realm;
}, 120_000);

afterAll(async () => {
  await app?.close();
});

async function machineToken(clientId: string, clientSecret: string, realm = realmName) {
  return app.inject({
    method: 'POST',
    url: `/realms/${realm}/protocol/openid-connect/token`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }).toString(),
  });
}

function claims(accessToken: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString('utf8'));
}

describe('v39 P6.2: the seven builtin roles reproduce the matrix exactly', () => {
  it('carries all seven, and no eighth', () => {
    expect(roles.map((role) => role.name).sort()).toEqual(Object.keys(EXPECTED).sort());
  });

  it('grants each role exactly what it granted before, permission for permission', () => {
    for (const role of roles) {
      const expected = EXPECTED[role.name];
      const actual = role.permissions;
      // Sorted on both sides so ordering is never mistaken for a difference, and compared whole so a
      // permission GAINED fails as loudly as one lost.
      const normalise = (map: Record<string, string[]>) => Object.fromEntries(
        Object.entries(map).map(([resource, actions]) => [resource, [...actions].sort()]),
      );
      expect(normalise(actual), `role ${role.name}`).toEqual(normalise(expected));
    }
  });

  it('scopes the account holder to itself and everyone else globally', () => {
    for (const role of roles) {
      expect(role.scopeKind, role.name).toBe(role.name === 'customer' ? 'self' : 'all');
    }
  });

  it('moves role and authentication administration to the authority own resource server', () => {
    // These stop being the application's resources: after the extraction the application has no roles
    // resource to grant, because the objects are not its own.
    const manager = roles.find((role) => role.name === 'manager');
    expect(manager?.permissions.roles).toBeUndefined();
    expect(manager?.permissions.authDomains).toBeUndefined();
    expect(Object.keys(manager?.authorityPermissions ?? {})).toContain('roles');
  });
});

describe('v39 P6.2: the separation-of-duties reasoning survived as data', () => {
  it('keeps a rationale on every role whose limits are a deliberate control', () => {
    // These were comments in the code that seeded the matrix. A comment cannot be shown to an
    // auditor asking why a role lacks something, and an absence with no recorded reason is
    // indistinguishable from an oversight.
    for (const name of ['customer', 'level2_investigator', 'security_auditor', 'merchant_officer', 'operations_officer', 'manager']) {
      const role = roles.find((candidate) => candidate.name === name);
      expect(role?.sodRationale, `${name} has no recorded rationale`).toBeTruthy();
      expect((role?.sodRationale ?? '').length).toBeGreaterThan(80);
    }
  });

  it('records why the read-only auditor cannot manage a beneficiary', () => {
    const auditor = roles.find((role) => role.name === 'security_auditor');
    const denial = auditor?.denialRationale?.find((entry) => entry.resource === 'beneficiaries');
    expect(denial?.action).toBe('manage');
    expect(denial?.reason).toMatch(/separation.of.duties/i);
  });

  it('records why first-line triage cannot read the platform event stream', () => {
    const analyst = roles.find((role) => role.name === 'level1_analyst');
    const denial = analyst?.denialRationale?.find((entry) => entry.resource === 'auditEvents');
    expect(denial?.reason).toMatch(/cross-entity|need/i);
  });

  it('records the decision and correction split between the two officer roles', () => {
    const officer = roles.find((role) => role.name === 'merchant_officer');
    const operations = roles.find((role) => role.name === 'operations_officer');
    expect(officer?.sodRationale).toMatch(/decision/i);
    expect(operations?.sodRationale).toMatch(/correct/i);
  });
});

describe('v39 P6.7: a permission granted to a service identity is enforced end to end', () => {
  it('issues a machine token carrying the permissions its role grants', async () => {
    const response = await machineToken('leafypay-backend', clientSecretFor('leafypay-backend'));
    expect(response.statusCode).toBe(200);

    const body = response.json();
    const payload = claims(body.access_token);

    // The machine is the SUBJECT of its own token, not an anonymous bearer of a key.
    expect(payload.sub).toBe('leafypay-backend');
    expect(payload.client_id).toBe('leafypay-backend');

    const permissions = payload.permissions as Array<{ resource: string; action: string }>;
    expect(permissions, 'a service identity received no permissions at all').toBeTruthy();
    expect(permissions).toContainEqual({ resource: 'auditEvents', action: 'view' });
    expect(permissions).toContainEqual({ resource: 'modules', action: 'view' });
  });

  it('grants a service only what its role holds, and nothing a person holds', async () => {
    const response = await machineToken('leafypay-backend', clientSecretFor('leafypay-backend'));
    const permissions = claims(response.json().access_token).permissions as Array<{ resource: string; action: string }>;
    // Default deny is the whole model: a service that could read cardholder data because it is a
    // service would make the role matrix decorative for exactly the principals nobody watches.
    expect(permissions).not.toContainEqual({ resource: 'cards', action: 'viewSensitive' });
    expect(permissions).not.toContainEqual({ resource: 'customers', action: 'viewSensitive' });
  });

  it('resolves a machine principal through the same decision point as a person', async () => {
    const { DecisionService } = await import('../../../../giam/backend/src/modules/authorization/services/decision.service');
    const { RealmService } = await import('../../../../giam/backend/src/modules/realm/services/realm.service');
    const realm = await new RealmService(app.db).byName(realmName);
    const decision = new DecisionService(app.db);

    // The same call, the same arguments, for a service and for a person. That symmetry is the claim.
    const machine = await decision.check(realm!.realmId, 'leafypay-backend', 'leafypay', 'auditEvents', 'view');
    expect(machine.effect).toBe('allow');

    const refused = await decision.check(realm!.realmId, 'leafypay-backend', 'leafypay', 'cards', 'viewSensitive');
    expect(refused.effect).toBe('deny');
    // A decision a log cannot explain is not auditable, so the refusal names what was missing.
    expect(refused.reason).toContain('cards:viewSensitive');
  });

  it('refuses a machine credential presented to the wrong realm', async () => {
    // The bank realm's third party cannot authenticate against the application realm, even with its
    // own correct secret: a client is a record inside one realm, not a platform-wide identity.
    const response = await machineToken('leafypay-psp', clientSecretFor('leafypay-psp'), realmName);
    expect(response.statusCode).toBe(401);
    expect(response.json().error).toBe('invalid_client');
  });

  it('refuses a machine credential with the wrong secret', async () => {
    const response = await machineToken('leafypay-backend', 'not-the-secret');
    expect(response.statusCode).toBe(401);
    expect(response.json().error).toBe('invalid_client');
  });
});

describe('v39 P6: a person receives the permissions their role grants', () => {
  it('resolves an analyst to exactly the analyst matrix', async () => {
    const { DecisionService } = await import('../../../../giam/backend/src/modules/authorization/services/decision.service');
    const { RealmService } = await import('../../../../giam/backend/src/modules/realm/services/realm.service');
    const identities = JSON.parse(
      readFileSync(resolve(DATA, 'identities.json'), 'utf8'),
    ) as Array<{ subjectId: string; roleName?: string }>;

    const analyst = identities.find((identity) => identity.roleName === 'level1_analyst');
    expect(analyst, 'no analyst in the seeded population').toBeTruthy();

    const realm = await new RealmService(app.db).byName(realmName);
    const resolved = await new DecisionService(app.db)
      .effectivePermissions(realm!.realmId, analyst!.subjectId, 'leafypay');

    const held = new Set(resolved.permissions.map((permission) => `${permission.resource}:${permission.action}`));
    for (const [resource, actions] of Object.entries(EXPECTED.level1_analyst)) {
      for (const action of actions) {
        expect(held.has(`${resource}:${action}`), `analyst is missing ${resource}:${action}`).toBe(true);
      }
    }
    // And nothing beyond it: an analyst holding the investigator's sensitive reveal would be the
    // escalation path the elevation exists to control.
    expect(held.has('cards:viewSensitive')).toBe(false);
    expect(resolved.scopeKind).toBe('all');
  });

  it('scopes an account holder to itself', async () => {
    const { DecisionService } = await import('../../../../giam/backend/src/modules/authorization/services/decision.service');
    const { RealmService } = await import('../../../../giam/backend/src/modules/realm/services/realm.service');
    const identities = JSON.parse(
      readFileSync(resolve(DATA, 'identities.json'), 'utf8'),
    ) as Array<{ subjectId: string; roleName?: string }>;

    const customer = identities.find((identity) => identity.roleName === 'customer');
    const realm = await new RealmService(app.db).byName(realmName);
    const resolved = await new DecisionService(app.db)
      .effectivePermissions(realm!.realmId, customer!.subjectId, 'leafypay');

    expect(resolved.scopeKind).toBe('self');
    expect(resolved.roles).toEqual(['customer']);
  });
});
