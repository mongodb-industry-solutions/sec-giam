import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { accountHolderForAudience } from '../../../backend/src/modules/oauth/services/accountHolderBinding';

const LEAFYPAY = 'b0000002-0000-4000-8000-000000000002';
const BANKCORE = 'hld00002-0000-4000-8000-000000000002';
const BOTH = { leafypay: LEAFYPAY, bankcore: BANKCORE };

describe('the account holder a token names', () => {
  it('is the one the addressed resource server knows the subject by', () => {
    expect(accountHolderForAudience(BOTH, LEAFYPAY, ['bankcore'])).toBe(BANKCORE);
    expect(accountHolderForAudience(BOTH, LEAFYPAY, ['leafypay'])).toBe(LEAFYPAY);
  });

  it('is the single reference for a subject bound to one application', () => {
    expect(accountHolderForAudience(undefined, LEAFYPAY, ['leafypay'])).toBe(LEAFYPAY);
  });

  it('falls back for an audience the bindings do not name', () => {
    expect(accountHolderForAudience({ bankcore: BANKCORE }, LEAFYPAY, ['leafypay'])).toBe(LEAFYPAY);
  });

  it('names nobody when the audience spans two different bindings', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // Fails closed: a self-scoped resource server refuses an unbound caller, which is the safe
    // answer. Serving one institution's records under the other's reference is not.
    expect(accountHolderForAudience(BOTH, LEAFYPAY, ['leafypay', 'bankcore'])).toBeUndefined();
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it('carries no binding when the subject has none', () => {
    expect(accountHolderForAudience(undefined, undefined, ['bankcore'])).toBeUndefined();
  });
});

describe('the demo population', () => {
  const read = (name: string) => JSON.parse(readFileSync(join(__dirname, '../../../backend/data', name), 'utf-8'));
  const identities = read('identities.json') as Array<Record<string, any>>;
  const customers = identities.filter((identity) => identity.roleName === 'customer');

  it('binds every customer to a record at BOTH institutions', () => {
    expect(customers.length).toBeGreaterThan(0);
    for (const customer of customers) {
      expect(customer.accountHolderRefs?.leafypay, `${customer.userName} at the provider`).toBeTruthy();
      expect(customer.accountHolderRefs?.bankcore, `${customer.userName} at the bank`).toBeTruthy();
      // The provider's binding must keep saying what it said before the map existed, or every token
      // already addressed to it changes meaning.
      expect(customer.accountHolderRefs.leafypay).toBe(customer.accountHolderRef);
    }
  });

  it('makes every customer an account holder at the bank as well', () => {
    for (const customer of customers) {
      expect(customer.additionalRoles, `${customer.userName}`).toContain('bank_customer');
    }
  });

  it('gives no two people the same record at either institution', () => {
    for (const audience of ['leafypay', 'bankcore']) {
      const refs = customers.map((customer) => customer.accountHolderRefs[audience]);
      expect(new Set(refs).size, `${audience} bindings are unique`).toBe(refs.length);
    }
  });

  it("lets an account holder read their own registered details at the bank", () => {
    const roles = read('bankRoles.json') as Array<Record<string, any>>;
    const holder = roles.find((role) => role.name === 'bank_customer');
    expect(holder.scopeKind, 'the role stays scoped to their own records').toBe('self');
    expect(holder.permissions.accountHolders).toContain('view');
    expect(holder.permissions.accounts).toContain('view');
    expect(holder.permissions.issuedCards).toContain('view');
    // Nothing that reaches another person's records, at any scope.
    expect(Object.values(holder.permissions).flat()).not.toContain('manage');
    expect(Object.values(holder.permissions).flat()).not.toContain('viewSensitive');
  });
});
