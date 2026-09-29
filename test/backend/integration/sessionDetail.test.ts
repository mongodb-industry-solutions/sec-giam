/**
 * One session in full, and ending several at once.
 *
 * Two claims. The detail surface must not become a way to enumerate sessions: a session belonging to
 * somebody else answers 404 to a caller who cannot reach it, never 403, because the pair of answers
 * together tells an attacker which identifiers are real.
 *
 * And it must not hand out a credential. No token is stored by this authority, so the assertion here
 * is that nothing token-shaped appears in the response at all: if a token registry is ever added,
 * this test is what stops it being published on a read surface by accident.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { endSession, issueTokenFor } from './support/authorizationFlow';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const CONSOLE = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
const REALM = 'LeafyIdp';

const opened: Array<{ token: string; sessionId: string }> = [];

async function signIn(login: string): Promise<{ token: string; sessionId: string }> {
  const issued = await issueTokenFor(GIAM, REALM, login, DEMO_PASSWORD, { client: CONSOLE });
  if (issued.sessionId) opened.push(issued);
  return issued;
}

afterAll(async () => {
  for (const session of opened) await endSession(GIAM, REALM, session.token, session.sessionId);
});

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

describe('a session in detail, and ending a selection', () => {
  let live = false;
  beforeAll(async () => { live = await reachable(); });

  it('answers for the caller own session, and carries no token', async () => {
    if (!live) return;
    const mine = await signIn('luis.fernandez');
    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/${mine.sessionId}`, {
      headers: { authorization: `Bearer ${mine.token}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const body = await response.text();
    const detail = JSON.parse(body) as {
      session: { sessionId: string; current: boolean };
      owner: { subjectId: string; userName?: string };
      authentication: { epoch: number; refreshGeneration: number; tokensStored: boolean };
    };

    expect(detail.session.sessionId).toBe(mine.sessionId);
    expect(detail.owner.userName).toBe('luis.fernandez');
    expect(detail.authentication.tokensStored).toBe(false);
    expect(typeof detail.authentication.epoch).toBe('number');
    expect(typeof detail.authentication.refreshGeneration).toBe('number');

    // Nothing token-shaped, and no JWT anywhere in the payload.
    expect(body).not.toMatch(/eyJ[A-Za-z0-9_-]{10,}/);
    for (const forbidden of ['access_token', 'accessToken', 'refresh_token', 'refreshToken', 'id_token']) {
      expect(body, `${forbidden} appeared on a read surface`).not.toContain(forbidden);
    }
    // No email or phone either: both are encrypted personal data and a session is not a reason to
    // decrypt them.
    expect(body).not.toContain('@');
  });

  it('is NOT FOUND, not refused, when the caller cannot reach it', async () => {
    if (!live) return;
    const target = await signIn('diego.sans');
    const other = await signIn('luis.fernandez');

    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/${target.sessionId}`, {
      headers: { authorization: `Bearer ${other.token}` },
      signal: AbortSignal.timeout(20000),
    });
    // 404 and never 403: the two answers together would confirm the identifier exists.
    expect(response.status).toBe(404);
  });

  it('lets a realm-wide role read somebody else session', async () => {
    if (!live) return;
    const target = await signIn('luis.fernandez');
    const manager = await signIn('alex.rivera');

    const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/${target.sessionId}`, {
      headers: { authorization: `Bearer ${manager.token}` },
      signal: AbortSignal.timeout(20000),
    });
    expect(response.status).toBe(200);
    const detail = await response.json() as { owner: { userName?: string }; session: { current: boolean } };
    expect(detail.owner.userName).toBe('luis.fernandez');
    expect(detail.session.current, 'somebody else session was reported as the caller own').toBe(false);
  });

  describe('ending a selection', () => {
    it('ends the ones it can and reports the rest as notFound, in one call', async () => {
      if (!live) return;
      // Three of the same persona, so the batch is unambiguous, plus one identifier that is not real.
      const first = await signIn('marta.oliveira');
      const second = await signIn('marta.oliveira');
      const manager = await signIn('alex.rivera');
      const invented = '00000000-0000-4000-8000-000000000000';

      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/terminate`, {
        method: 'POST',
        headers: { authorization: `Bearer ${manager.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ sessionIds: [first.sessionId, second.sessionId, invented] }),
        signal: AbortSignal.timeout(60000),
      });
      expect(response.status).toBe(200);
      const outcome = await response.json() as {
        terminated: number;
        wasCurrentSession: boolean;
        results: { sessionId: string; outcome: string }[];
      };

      expect(outcome.terminated).toBe(2);
      expect(outcome.wasCurrentSession).toBe(false);
      const byId = new Map(outcome.results.map((result) => [result.sessionId, result.outcome]));
      expect(byId.get(first.sessionId)).toBe('terminated');
      expect(byId.get(second.sessionId)).toBe('terminated');
      // An invented identifier is reported exactly as an unreachable one would be.
      expect(byId.get(invented)).toBe('notFound');

      // And they are really gone, not merely reported gone.
      for (const ended of [first.sessionId, second.sessionId]) {
        const check = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/${ended}`, {
          headers: { authorization: `Bearer ${manager.token}` },
          signal: AbortSignal.timeout(20000),
        });
        expect(check.status).toBe(404);
      }
    }, 120000);

    it('refuses to end somebody else sessions without a realm-wide role', async () => {
      if (!live) return;
      const target = await signIn('diego.sans');
      const ordinary = await signIn('luis.fernandez');

      const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/terminate`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ordinary.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ sessionIds: [target.sessionId] }),
        signal: AbortSignal.timeout(20000),
      });
      expect(response.status).toBe(200);
      const outcome = await response.json() as { terminated: number; results: { outcome: string }[] };
      // Nothing ended, and reported as notFound rather than refused, so a batch cannot be used to
      // discover which identifiers are real either.
      expect(outcome.terminated).toBe(0);
      expect(outcome.results[0].outcome).toBe('notFound');

      // The target is untouched.
      const still = await fetch(`${GIAM}/api/v1/realms/${REALM}/sessions/${target.sessionId}`, {
        headers: { authorization: `Bearer ${target.token}` },
        signal: AbortSignal.timeout(20000),
      });
      expect(still.status).toBe(200);
    });
  });
});
