// A case-scoped elevation, asked for by the investigator who already holds the role standing.
//
// This is the flow the endpoint exists for, and it was refused outright by two faults that hid each
// other. The request body carries `scopeKind`/`scopeRef` as flat fields, under
// `additionalProperties: false`, so a handler reading `body.scope` read undefined every time: every
// elevation arrived unscoped, the duplicate check compared it against the caller's own STANDING
// holding of the same role (also unscoped), and answered 409 "already held" on the first attempt.
// Then, with the scope arriving, a repeat of the identical request still answered 409, so a page
// reload or a second tab could not recover the grant it already held.
//
// Both are asserted against the running authority rather than reasoned about, because both were
// invisible in the code that produced them: one is a field name, the other is a comparison that was
// right in general and wrong for the case that matters.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { tokenFor } from './support/authorizationFlow';
import { withDirectDb } from './support/directDb';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const PLATFORM = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };
const DEMO_PASSWORD = 'demo-password';
/** A standing level 2 investigator: the holding that made the duplicate check refuse the request. */
const INVESTIGATOR = 'michael.obi';
const ROLE = 'level2_investigator';
const CASE = `case-${Math.random().toString(36).slice(2, 8)}`;

interface Elevation {
  subjectId: string;
  roleId: string;
  scope?: { kind: string; ref: string };
  grantedAt: string;
  expiresAt?: string;
  ephemeral?: boolean;
  pendingApproval?: boolean;
}

describe('a scoped elevation, self-requested by the standing holder', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    token = await tokenFor(GIAM, 'leafypay', INVESTIGATOR, DEMO_PASSWORD, { client: PLATFORM });
  });

  /** The test's own ephemeral holding, on a seeded principal that must survive it. */
  afterAll(async () => {
    if (!live) return;
    await withDirectDb(async (db) => {
      await db.collection('principal').updateMany(
        {},
        { $pull: { roles: { 'scope.ref': CASE } } } as never,
      );
    }).catch(() => {});
  });

  const request = async () => fetch(`${GIAM}/realms/leafypay/elevations`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      roleName: ROLE,
      scopeKind: 'case',
      scopeRef: CASE,
      justification: 'reviewing the escalated case',
      durationSeconds: 900,
    }),
    signal: AbortSignal.timeout(20000),
  });

  it('carries the scope from the flat body through to the grant', async () => {
    if (!live) return;
    const response = await request();
    expect(response.status, await response.clone().text()).toBe(200);

    const granted = await response.json() as Elevation;
    // The whole fault in one assertion: unscoped here is what made it collide with the standing role.
    expect(granted.scope).toEqual({ kind: 'case', ref: CASE });
  });

  /**
   * In force, not awaiting a reviewer.
   *
   * `leafypay` sets `requiresElevationApproval: false`, because the review in this flow is the L2
   * accepting the escalation: there is no second reviewer and nothing calls `/approve`, so
   * defaulting to "needs approval" left a single-actor grant permanently pending.
   */
  it('is in force immediately in a realm that reviews before it asks', async () => {
    if (!live) return;
    const granted = await (await request()).json() as Elevation;
    expect(granted.ephemeral).toBe(true);
    expect(granted.expiresAt).toBeTruthy();
    expect(granted.pendingApproval ?? false).toBe(false);
  });

  /**
   * The same subject asking again for the same role and scope.
   *
   * It grants nothing they do not already hold, so answering is a re-derivation rather than a second
   * elevation, and refusing it is what stopped a reload from recovering the grant.
   */
  it('answers a repeat with the grant already held rather than refusing it', async () => {
    if (!live) return;
    const first = await (await request()).json() as Elevation;
    const again = await request();

    expect(again.status).toBe(200);
    const repeated = await again.json() as Elevation;
    // The SAME grant, not a fresh one: a new grantedAt would mean the window had been extended by
    // asking twice, which is a different and worse answer than either refusing or re-deriving.
    expect(repeated.grantedAt).toBe(first.grantedAt);
    expect(repeated.scope).toEqual(first.scope);
  });
});
