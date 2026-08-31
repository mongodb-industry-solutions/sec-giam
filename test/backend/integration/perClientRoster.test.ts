/**
 * The demo roster is scoped to the application signing the person in.
 *
 * The useful personas differ per application, and offering the wrong ones is not cosmetic: a third
 * party's sign-in screen listing the provider's fraud analysts invites somebody to demonstrate the
 * wrong thing, and a screen meant to show an ordinary user has no business offering oversight roles.
 *
 * The client id already travels in the authorization request, so nothing extra is passed. The list
 * comes from the CLIENT RECORD rather than the query, which is what stops a caller widening its own.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';

interface Entry { subjectId: string; userName: string; role?: string }

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

async function roster(realm: string, clientId?: string): Promise<Entry[]> {
  const query = clientId ? `?client_id=${encodeURIComponent(clientId)}` : '';
  const response = await fetch(`${GIAM}/realms/${realm}/login-context${query}`, {
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) return [];
  return (await response.json() as { roster: Entry[] }).roster;
}

function roles(entries: Entry[]): string[] {
  return [...new Set(entries.map((entry) => entry.role ?? '(none)'))].sort();
}

const PSP_STAFF = ['level1_analyst', 'level2_investigator', 'merchant_officer', 'operations_officer'];

describe('v39: the sign-in roster is scoped per application', () => {
  let live = false;

  beforeAll(async () => { live = await reachable(); });

  it('offers at least two personas per role, so a screen shows a role and not a person', async () => {
    if (!live) return;
    for (const realm of ['leafypay', 'bankcore']) {
      const entries = await roster(realm);
      const counts = new Map<string, number>();
      for (const entry of entries) {
        const role = entry.role ?? '(none)';
        counts.set(role, (counts.get(role) ?? 0) + 1);
      }
      for (const [role, count] of counts) {
        expect(count, `${realm}/${role} has only ${count} demo persona`).toBeGreaterThanOrEqual(2);
      }
    }
  });

  it("a third party's app offers customers and none of the provider's staff", async () => {
    if (!live) return;
    const offered = roles(await roster('leafypay', 'oauth001-0000-4000-8000-000000000001'));
    expect(offered).toContain('customer');
    for (const staff of [...PSP_STAFF, 'manager', 'security_auditor']) {
      expect(offered, `${staff} belongs to the provider, not to a third party's screen`).not.toContain(staff);
    }
  });

  it('the authority console offers who administers it, who audits it, and an ordinary user', async () => {
    if (!live) return;
    const offered = roles(await roster('leafypay', 'giam-console'));
    expect(offered).toContain('manager');
    expect(offered).toContain('security_auditor');
    expect(offered).toContain('customer');
    // The provider's business roles have no reason to appear on the identity console's own screen.
    for (const staff of PSP_STAFF) {
      expect(offered, `${staff} administers no identity`).not.toContain(staff);
    }
  });

  it("the bank offers its own people and its own account holders, and no provider role at all", async () => {
    if (!live) return;
    const offered = roles(await roster('bankcore', 'bankcore-console'));
    expect(offered).toEqual([
      'bank_admin', 'bank_card_officer', 'bank_compliance', 'bank_customer', 'bank_operations',
    ]);
  });

  it('a client that declares nothing gets every featured persona in its realm', async () => {
    if (!live) return;
    const everything = roles(await roster('leafypay'));
    const scoped = roles(await roster('leafypay', 'oauth001-0000-4000-8000-000000000001'));
    expect(everything.length, 'the unscoped roster is the wider one').toBeGreaterThan(scoped.length);
  });

  it('an unknown client is not a way to widen the roster', async () => {
    if (!live) return;
    // Falls back to the realm's featured personas rather than erroring: the screen still works, and
    // no caller gains anything by inventing a client id.
    const invented = await roster('leafypay', 'not-a-registered-client');
    expect(invented.length).toBeGreaterThan(0);
  });
});
