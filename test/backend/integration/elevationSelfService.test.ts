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
        { $pull: { roles: { 'scope.ref': { $in: [CASE, `${CASE}-expired`] } } } } as never,
      );
    }).catch(() => {});
  });

  const request = async () => fetch(`${GIAM}/api/v1/realms/leafypay/elevations`, {
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
  /**
   * An expiry that did not merely end the access, it made the scope unusable for good.
   *
   * A spent holding still matched the duplicate check, so the re-derivation branch above handed the
   * dead entry back on the happy path: the resource server read a success, told the investigator
   * they were elevated, and every check against the scope went on answering "not in force". Nothing
   * swept the entry either, so the case could never be elevated again by that person. What follows
   * is the re-derivation test's twin, and the two must disagree: an in-force grant is returned as
   * it stands, an expired one is replaced.
   */
  it('re-grants a scope whose earlier elevation has expired', async () => {
    if (!live) return;
    const expiredScope = `${CASE}-expired`;
    const requestFor = async (ref: string) => fetch(`${GIAM}/api/v1/realms/leafypay/elevations`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        roleName: ROLE, scopeKind: 'case', scopeRef: ref,
        justification: 'reviewing the escalated case', durationSeconds: 900,
      }),
      signal: AbortSignal.timeout(20000),
    });
    const inForce = async (ref: string) => {
      const response = await fetch(
        `${GIAM}/api/v1/realms/leafypay/elevations/mine?scopeKind=case&scopeRef=${encodeURIComponent(ref)}`,
        { headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(20000) },
      );
      return (await response.json() as { inForce: boolean }).inForce;
    };

    const first = await (await requestFor(expiredScope)).json() as Elevation;
    expect(await inForce(expiredScope)).toBe(true);

    // Aged past its expiry rather than waited out: the shortest grant this endpoint issues still
    // outlives any test worth running.
    await withDirectDb(async (db) => {
      await db.collection('principal').updateOne(
        { 'roles.scope.ref': expiredScope },
        { $set: { 'roles.$.expiresAt': new Date(Date.now() - 60_000).toISOString() } },
      );
    });
    expect(await inForce(expiredScope)).toBe(false);

    const again = await requestFor(expiredScope);
    expect(again.status, await again.clone().text()).toBe(200);
    const regranted = await again.json() as Elevation;
    // A NEW grant, which is the whole point: same scope, its own clock, and usable.
    expect(regranted.grantedAt).not.toBe(first.grantedAt);
    expect(Date.parse(regranted.expiresAt as string)).toBeGreaterThan(Date.now());
    expect(await inForce(expiredScope)).toBe(true);
  });

  /**
   * Proving your OWN elevation, which is the question the holder can actually ask.
   *
   * `GET /elevations` is oversight ("who holds elevated access") and is permissioned as one:
   * `elevations:view`, which `level2_investigator` does not hold and should not. So the only check
   * available to a resource server was one the caller holding the elevation was itself refused,
   * and an elevation that cannot be checked cannot be exercised. `/elevations/mine` answers the
   * narrower question, about the subject in the token and no other.
   */
  it('lets the holder prove their own elevation without the oversight permission', async () => {
    if (!live) return;
    const headers = { authorization: `Bearer ${token}` };
    const mine = async (ref: string) => {
      const response = await fetch(
        `${GIAM}/api/v1/realms/leafypay/elevations/mine?scopeKind=case&scopeRef=${encodeURIComponent(ref)}`,
        { headers, signal: AbortSignal.timeout(20000) },
      );
      expect(response.status).toBe(200);
      return (await response.json() as { inForce: boolean }).inForce;
    };

    // Granted above by the earlier cases in this file, which share CASE.
    await request();
    expect(await mine(CASE)).toBe(true);
    // A scope nobody was elevated for. `false` rather than a refusal: the absence IS the answer.
    expect(await mine(`${CASE}-never-granted`)).toBe(false);

    /**
     * And the narrow question does not smuggle in the wide one.
     *
     * If this ever stops being 403, the holder of any elevated role can enumerate everybody else's,
     * which is the reason the two questions are separate routes rather than one with a flag.
     */
    const oversight = await fetch(`${GIAM}/api/v1/realms/leafypay/elevations`, { headers, signal: AbortSignal.timeout(20000) });
    expect(oversight.status).toBe(403);
  });

});
