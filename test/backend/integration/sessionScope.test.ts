/**
 * Whose sessions a caller sees depends on the scope of the role they hold.
 *
 * The claim: an ordinary registered user sees only their own, and a realm administrator sees every
 * live session in the realm. The narrowing is the authority's, never the console's, so asking for
 * `scope=realm` without a realm-wide role must narrow the answer or refuse it, not leak it.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { endSession, issueTokenFor } from './support/authorizationFlow';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const CONSOLE = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
const REALM = 'LeafyIdp';

interface Persona {
  label: string;
  login: string;
  /** What `scope=realm` must answer, and what the caller's own permissions must say. */
  realmScope: 'realm' | 403;
  mayManage: boolean;
}

/**
 * Every session these tests opened, ended when they finish.
 *
 * Signing a persona in through the real flow creates a real session, and a suite that never closes
 * them leaves one per login alive for the length of its idle window. Run a few times, that is a
 * demo whose sessions screen is full of sessions nobody is using: correct records of nothing, which
 * is indistinguishable from a bug to whoever is looking at the screen.
 */
const opened: Array<{ token: string; sessionId: string }> = [];

async function runFlow(
  giam: string,
  realm: string,
  login: string,
  password: string,
  options: Parameters<typeof issueTokenFor>[4],
): Promise<string> {
  const issued = await issueTokenFor(giam, realm, login, password, options);
  if (issued.sessionId) opened.push(issued);
  return issued.token;
}

afterAll(async () => {
  for (const session of opened) await endSession(GIAM, REALM, session.token, session.sessionId);
});

const PERSONAS: Persona[] = [
  { label: 'manager', login: 'alex.rivera', realmScope: 'realm', mayManage: true },
  { label: 'security auditor', login: 'diego.sans', realmScope: 'realm', mayManage: false },
  { label: 'customer', login: 'luis.fernandez', realmScope: 403, mayManage: false },
];

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

describe('sessions: the realm-wide view is gated by the role, not by the console', () => {
  let live = false;
  beforeAll(async () => { live = await reachable(); });

  for (const persona of PERSONAS) {
    it(`${persona.label}: scope=realm answers ${persona.realmScope}`, async () => {
      if (!live) return;
      const token = await runFlow(GIAM, 'leafypay', persona.login, DEMO_PASSWORD, { client: CONSOLE });
      expect(token, `${persona.login} could not sign in`).toBeTruthy();
      const headers = { authorization: `Bearer ${token}` };

      const mine = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions`, { headers, signal: AbortSignal.timeout(20000) });
      expect(mine.status).toBe(200);
      const own = await mine.json() as { scope: string; total: number };
      expect(own.scope).toBe('mine');
      expect(own.total).toBeGreaterThan(0);

      const wide = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?scope=realm`, { headers, signal: AbortSignal.timeout(20000) });
      if (persona.realmScope === 403) {
        expect(wide.status).toBe(403);
      } else {
        expect(wide.status).toBe(200);
        const all = await wide.json() as { scope: string; total: number };
        expect(all.scope).toBe('realm');
        // The realm-wide answer must be a superset: at minimum the caller's own session is in it.
        expect(all.total).toBeGreaterThanOrEqual(own.total);
      }
    });

    it(`${persona.label}: /me/permissions agrees with what the sessions endpoint does`, async () => {
      if (!live) return;
      const token = await runFlow(GIAM, 'leafypay', persona.login, DEMO_PASSWORD, { client: CONSOLE });
      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/me/permissions`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(200);
      const me = await response.json() as { permissions: string[]; scopeKind: string };

      // What the console gates the "everyone in this realm" control on must match the gate the
      // authority applies: the permission AND the realm-wide scope, never the permission alone.
      const reachesOthers = me.permissions.includes('sessions:view') && me.scopeKind === 'all';
      expect(reachesOthers).toBe(persona.realmScope === 'realm');
      expect(me.permissions.includes('sessions:manage') && me.scopeKind === 'all').toBe(persona.mayManage);
    });
  }
  /**
   * The realm-wide answer contains OTHER people, not just more of the caller.
   *
   * The earlier assertion was only that the realm total is at least the own one of the caller, which a
   * `listForRealm` that had quietly narrowed to the caller would also satisfy. This signs a second
   * persona in first and then demands to find THAT subject in the manager's answer, which is the
   * claim the screen actually makes.
   */
  it('the manager sees a session belonging to somebody else, not only their own', async () => {
    if (!live) return;
    const customerToken = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
    expect(customerToken).toBeTruthy();
    const customerSub = JSON.parse(
      Buffer.from(customerToken.split('.')[1], 'base64url').toString('utf8'),
    ).sub as string;

    const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: CONSOLE });
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?scope=realm&limit=200`, {
      headers: { authorization: `Bearer ${managerToken}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const all = await response.json() as { sessions: { subjectId: string }[] };

    const subjects = new Set(all.sessions.map((session) => session.subjectId));
    expect(subjects.size, 'the realm view collapsed to a single principal').toBeGreaterThan(1);
    expect([...subjects]).toContain(customerSub);
  });
  /**
   * The filters narrow, and narrowing is never a way around the entitlement.
   *
   * The application filter is open to everybody, because narrowing your OWN sessions to one
   * application says nothing about anybody else. The people search is not, and asking for it without
   * a realm-wide role must be refused rather than quietly answered about yourself.
   */
  describe('the filters', () => {
    it('offers the applications of the realm by name', async () => {
      if (!live) return;
      const token = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(200);
      const answer = await response.json() as {
        applications: { clientId: string; clientName: string }[];
        sessions: { clientIds: string[]; applications: string[] }[];
      };

      // The console the caller just signed in through must be offerable by name.
      const console_ = answer.applications.find((application) => application.clientId === CONSOLE.clientId);
      expect(console_, 'the signing-in application was not offered as a filter option').toBeTruthy();
      expect(console_!.clientName.length).toBeGreaterThan(0);

      // Every row names its applications, one entry per client id and never fewer.
      for (const session of answer.sessions) {
        expect(session.applications.length).toBe(session.clientIds.length);
      }
    });

    it('narrows to one application, and to none for an application holding nothing', async () => {
      if (!live) return;
      const token = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
      const headers = { authorization: `Bearer ${token}` };

      const held = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?clientId=${CONSOLE.clientId}`, {
        headers, signal: AbortSignal.timeout(20000),
      });
      expect(held.status).toBe(200);
      const matching = await held.json() as { sessions: { clientIds: string[] }[]; total: number };
      expect(matching.total).toBeGreaterThan(0);
      for (const session of matching.sessions) {
        expect(session.clientIds).toContain(CONSOLE.clientId);
      }

      const none = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?clientId=no-such-application`, {
        headers, signal: AbortSignal.timeout(20000),
      });
      expect(none.status).toBe(200);
      expect((await none.json() as { total: number }).total).toBe(0);
    });

    it('refuses the people search to a caller who does not reach other people', async () => {
      if (!live) return;
      const token = await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?q=alex`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(20000),
      });
      // Refused, not answered about themselves: a search that silently changed subject would read
      // as "alex has no sessions" to somebody who may not ask the question at all.
      expect(response.status).toBe(403);
    });

    it('finds a person by name for a caller who does reach them', async () => {
      if (!live) return;
      await runFlow(GIAM, 'leafypay', 'luis.fernandez', DEMO_PASSWORD, { client: CONSOLE });
      const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: CONSOLE });

      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?scope=realm&q=luis.fernandez&limit=200`, {
        headers: { authorization: `Bearer ${managerToken}` },
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(200);
      const found = await response.json() as { sessions: { userName?: string }[]; total: number };
      expect(found.total).toBeGreaterThan(0);
      // Only the person searched for, never the whole realm with the term ignored.
      for (const session of found.sessions) {
        expect(session.userName).toBe('luis.fernandez');
      }
    });

    it('answers nothing, rather than everything, when the search matches nobody', async () => {
      if (!live) return;
      const managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', DEMO_PASSWORD, { client: CONSOLE });
      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions?scope=realm&q=nobody-by-this-name`, {
        headers: { authorization: `Bearer ${managerToken}` },
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(200);
      expect((await response.json() as { total: number }).total).toBe(0);
    });
  });
});
