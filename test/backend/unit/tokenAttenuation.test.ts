// v40 P9: a token may only NARROW what the roles grant, never widen it.
//
// This is the invariant that makes it safe for a client to ask for specific permissions at all. If
// asking could widen, every client would ask for everything and the narrow request would be a
// liability rather than a feature. Both directions are tested, because only one of them is the
// obvious one: that a legitimate narrowing works, and that an illegitimate widening is dropped.
import { describe, it, expect } from 'vitest';
import { attenuate, claimsSize } from '../../../backend/src/modules/oauth/services/attenuate';

const HELD = ['payments:read', 'payments:refund', 'accounts:read'];
const ROLES = ['operator', 'reviewer'];

describe('P9.1 P9.2: roles by default, because a header has a size limit', () => {
  it('carries roles and NO permissions when the client asks for nothing', () => {
    // The default, and the only form that scales: a proxy cutting around 8 KB turns a token full of
    // expanded permissions into an intermittent production failure that depends on the route taken.
    const carried = attenuate({ held: HELD, roles: ROLES });
    expect(carried.roles).toEqual(ROLES);
    expect(carried.permissions).toEqual([]);
    expect(carried.dropped).toEqual([]);
  });

  it('treats an empty request as no request rather than as a request for nothing', () => {
    // A client sending `permissions=` should get the default, not a token carrying no authority.
    expect(attenuate({ held: HELD, requested: [], roles: ROLES }).roles).toEqual(ROLES);
  });
});

describe('P9.3 P9.4: the invariant, in both directions', () => {
  it('narrows to what was asked for, when the roles grant it', () => {
    const carried = attenuate({ held: HELD, requested: ['payments:read'], roles: ROLES });
    expect(carried.permissions).toEqual(['payments:read']);
    expect(carried.dropped).toEqual([]);
  });

  it('DROPS what the roles do not grant, rather than granting it', () => {
    // The direction that matters. A client asking for something its subject does not hold must not
    // receive it, however it asked.
    const carried = attenuate({
      held: HELD,
      requested: ['payments:read', 'payments:approve', 'ledger:write'],
      roles: ROLES,
    });
    expect(carried.permissions).toEqual(['payments:read']);
    expect(carried.dropped).toEqual(['ledger:write', 'payments:approve']);
  });

  it('never returns more than was held, whatever is asked for', () => {
    const carried = attenuate({ held: HELD, requested: HELD.concat(['everything:always']), roles: ROLES });
    for (const permission of carried.permissions) {
      expect(HELD, `${permission} was not held`).toContain(permission);
    }
  });

  it('refuses a wildcard, which would be a widening dressed as a narrowing', () => {
    const carried = attenuate({ held: HELD, requested: ['*'], roles: ROLES });
    expect(carried.permissions).toEqual([]);
    expect(carried.dropped).toEqual(['*']);
  });

  it('drops everything when the subject holds nothing, and does not fall back to the roles', () => {
    // Falling back would be the widening again, at the moment it is least visible.
    const carried = attenuate({ held: [], requested: ['payments:read'], roles: ROLES });
    expect(carried.permissions).toEqual([]);
    expect(carried.dropped).toEqual(['payments:read']);
  });

  it('keeps the roles alongside a narrowed set, so a role-checking server still works', () => {
    // Dropping the roles here would silently break every resource server that enforces roles, the
    // moment any client started narrowing.
    const carried = attenuate({ held: HELD, requested: ['payments:read'], roles: ROLES });
    expect(carried.roles).toEqual(ROLES);
  });

  it('reports the drop, because a drop nobody can see is a client operating on a wrong belief', () => {
    const carried = attenuate({ held: HELD, requested: ['nope:never'], roles: ROLES });
    expect(carried.dropped).toEqual(['nope:never']);
  });
});

describe('P9.6: a token for ten roles stays under 4 KB', () => {
  it('measures the claims rather than assuming they are small enough', () => {
    /**
     * The number that actually bites is the ~8 KB header limit, and "it should be fine" is how a
     * token ends up too large on one proxy and fine on every other. So this measures.
     *
     * Ten roles with realistic names, plus the claims a real access token carries.
     */
    const roles = [
      'realm_administrator', 'client_administrator', 'level1_analyst', 'level2_analyst',
      'compliance_reviewer', 'payments_operator', 'merchant_support', 'customer',
      'fraud_investigator', 'audit_reader',
    ];
    const claims = {
      iss: 'https://authority.example/realms/leafypay',
      aud: ['https://api.example/payments', 'https://api.example/accounts'],
      sub: 'a1000070-0000-4000-8000-000000000070',
      jti: '5f1b8c2e-4a7d-4e91-b3c6-8d2f1a9e7b40',
      iat: 1788374692,
      nbf: 1788374692,
      exp: 1788374992,
      scope: 'openid profile payments.read payments.write accounts.read',
      client_id: 'leafypay-console',
      sid: 'c4e2a8f1-9b3d-4c76-a5e8-2f7b1d6c9a34',
      session_epoch: 3,
      roles,
    };
    const size = claimsSize(claims);
    expect(size, `claims are ${size} bytes`).toBeLessThan(4096);
  });

  it('shows why roles rather than expanded permissions is the scaling choice', () => {
    // Not an assertion about a limit, but about the ratio the design rests on: the same authority
    // expanded into permissions is several times larger, and that is the whole argument.
    const roles = Array.from({ length: 10 }, (_, i) => `role_number_${i}`);
    const expanded = Array.from({ length: 300 }, (_, i) => `resource${i % 30}:action${i % 10}`);
    expect(claimsSize({ roles })).toBeLessThan(claimsSize({ permissions: expanded }));
    expect(claimsSize({ permissions: expanded })).toBeGreaterThan(4096);
  });
});
