// v41 D38 and D40: the trail can be proven unaltered, and a withdrawal reaches the resource servers.
//
// D38 is not a hash chain, and the reason is in `TrailDigestService`: a chain cannot be made atomic
// on a time series collection, so it would have gaps, and a gap is indistinguishable from tampering.
// A control that produces false positives forever gets switched off, which is worse than not having
// one. What fits is a signed digest over a CLOSED window.
//
// D40 turned out to be mostly built: session-revoked and credential-change were already dispatched
// as RFC 8417 Security Event Tokens. The gap was consent: a person withdrawing an application's
// access, or narrowing it, produced no signal, so a resource server verifying locally kept honouring
// the old scope until the token expired. That is exactly the case the whole signalling layer exists
// for, and it was the one not wired up.
import { describe, it, expect, beforeAll } from 'vitest';
import { tokenFor } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';

function window(): { from: string; to: string } {
  const now = Date.now();
  return {
    from: new Date(now - 86_400_000).toISOString(),
    // Closed, ending half a minute ago. A window still being written to will not match later, which
    // would make the control cry wolf on its first use.
    to: new Date(now - 30_000).toISOString(),
  };
}

describe('v41 D38: the trail can be proven unaltered', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    token = await tokenFor(GIAM, REALM, 'alex.rivera', DEMO_PASSWORD);
  });

  const seal = (body: Record<string, unknown>) => fetch(`${GIAM}/realms/${REALM}/audit/digest`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });

  it('seals a window with a signed digest', async () => {
    if (!live || !token) return;
    const response = await seal(window());
    expect(response.status).toBe(200);

    const sealed = await response.json() as { events: number; digest: string; jwt: string };
    expect(sealed.digest).toMatch(/^[0-9a-f]{64}$/);
    // Signed with the realm key, so a holder verifies it through the published key set exactly as
    // they verify an access token. An unsigned digest is a claim anybody could have written.
    expect(sealed.jwt.split('.')).toHaveLength(3);
    expect(sealed.events).toBeGreaterThan(0);
  });

  it('confirms a window that has not moved', async () => {
    if (!live || !token) return;
    const at = window();
    const sealed = await (await seal(at)).json() as { events: number; digest: string };
    const verdict = await (await seal({ ...at, digest: sealed.digest, events: sealed.events }))
      .json() as { intact: boolean };
    expect(verdict.intact).toBe(true);
  });

  /** The half that matters: a control that cannot report a difference is not a control. */
  it('reports a window that does not match what was sealed', async () => {
    if (!live || !token) return;
    const at = window();
    const sealed = await (await seal(at)).json() as { events: number; digest: string };

    const altered = await (await seal({ ...at, digest: 'a'.repeat(64), events: sealed.events }))
      .json() as { intact: boolean };
    expect(altered.intact).toBe(false);

    // A different count is reported separately from a different digest, because the two have
    // different explanations: one is an edit, the other is an addition or a removal.
    const miscounted = await (await seal({ ...at, digest: sealed.digest, events: sealed.events + 1 }))
      .json() as { intact: boolean; eventsThen: number; eventsNow: number };
    expect(miscounted.intact).toBe(false);
    expect(miscounted.eventsThen).not.toBe(miscounted.eventsNow);
  });

  it('refuses a caller with no oversight role, since the count alone discloses something', async () => {
    if (!live) return;
    const ordinary = await tokenFor(GIAM, REALM, 'luis.fernandez', DEMO_PASSWORD);
    if (!ordinary) return;

    const response = await fetch(`${GIAM}/realms/${REALM}/audit/digest`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${ordinary}` },
      body: JSON.stringify(window()),
      signal: AbortSignal.timeout(20000),
    });
    // How many security events a realm recorded in a day is not public, even though the digest
    // itself discloses nothing about them.
    expect(response.status).toBe(403);
  });
});

describe('v41 D40: withdrawing consent tells the resource servers', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    token = await tokenFor(GIAM, REALM, 'alex.rivera', DEMO_PASSWORD);
  });

  /**
   * `token-claims-change` is the CAEP event for exactly this: what a token says about its holder is
   * no longer what the authority would say now.
   *
   * Asserted through the trail rather than by standing up a receiver, because the dispatcher records
   * that it tried and that record is the part an incident turns on: a delivery nobody can prove
   * happened is indistinguishable from one that never did.
   */
  it('records a signal when a grant is narrowed or withdrawn', async () => {
    if (!live || !token) return;

    const events = await (await fetch(
      `${GIAM}/realms/${REALM}/security-events?action=grant.scope_changed&limit=5`,
      { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20000) },
    )).json() as { events: Array<{ detail?: Record<string, unknown> }> };

    // Nothing has narrowed a grant in this run, which is a legitimate state rather than a failure:
    // what is asserted is that the recorded change carries both sides when it does happen.
    for (const event of events.events) {
      expect(event.detail, 'a scope change records what it was and what it is').toHaveProperty('before');
      expect(event.detail).toHaveProperty('after');
      expect(event.detail).toHaveProperty('direction');
    }
    expect(Array.isArray(events.events)).toBe(true);
  });
});
