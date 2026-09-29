// v41 P10: an audit that starts from a captured token and reaches everything.
//
// This is the capability the whole forensic half of v41 exists for. Before it, an investigator
// holding an access token had nothing to pivot on: `correlationId` was per HTTP request, the only
// thing grouping an authorization with its redemption was a hash of the client's optional `state`,
// and nothing in a token led back to its own events.
//
// The assertion that would fail silently is the authorization one at the bottom. A `txn` is readable
// by anybody who holds the token, so an endpoint that returned a flow to whoever asked would be a
// master key, and it would pass every functional assertion above it.
import { describe, it, expect, beforeAll } from 'vitest';
import { createHash, randomBytes } from 'crypto';
import { signIn, CONSOLE_CLIENT } from './support/authorizationFlow';

const GIAM = process.env.GIAM_URL ?? 'http://127.0.0.1:8085';
const REALM = 'leafypay';
const DEMO_PASSWORD = 'demo-password';

/** An administrator, so the oversight branch of the permission check is the one exercised. */
const OVERSIGHT = 'alex.rivera';
/** Somebody with no oversight role, for the branch that must answer 404. */
const ORDINARY = 'luis.fernandez';

function decode(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')) as Record<string, unknown>;
}

/** Signs in and runs the flow, returning the token so a test can decompose it like an auditor would. */
async function tokenFor(login: string): Promise<{ access: string; claims: Record<string, unknown> } | null> {
  const session = await signIn(GIAM, REALM, login, DEMO_PASSWORD);
  if (!session) return null;

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const url = new URL(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/auth`);
  for (const [key, value] of Object.entries({
    client_id: CONSOLE_CLIENT.clientId,
    redirect_uri: CONSOLE_CLIENT.redirectUri,
    response_type: 'code',
    scope: 'openid profile',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })) url.searchParams.set(key, value);

  const authorize = await fetch(url, {
    headers: { cookie: session.cookie }, redirect: 'manual', signal: AbortSignal.timeout(20000),
  });
  const code = new URL(authorize.headers.get('location') as string).searchParams.get('code');
  if (!code) return null;

  const response = await fetch(`${GIAM}/api/v1/realms/${REALM}/protocol/oidc/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: CONSOLE_CLIENT.redirectUri,
      client_id: CONSOLE_CLIENT.clientId,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) return null;
  const access = (await response.json() as { access_token: string }).access_token;
  return { access, claims: decode(access) };
}

describe('v41 P10: everything about one flow, from the token alone', () => {
  let live = false;
  let held: { access: string; claims: Record<string, unknown> } | null = null;

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    held = await tokenFor(OVERSIGHT);
  });

  const asHolder = (path: string, token: string) => fetch(`${GIAM}/api/v1/realms/${REALM}${path}`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(20000),
  });

  it('carries both identifiers, which is what makes the pivot possible at all', () => {
    if (!live) return;
    expect(held?.claims.jti, 'jti names the token').toBeTruthy();
    expect(held?.claims.txn, 'txn names the flow').toBeTruthy();
    // Orthogonal axes: one token, one flow. Reusing `jti` for both would break replay detection.
    expect(held?.claims.jti).not.toBe(held?.claims.txn);
  });

  it('resolves a token to its flow, which is the entry point when only a token is held', async () => {
    if (!live || !held) return;
    const response = await asHolder(`/audit/tokens/${held.claims.jti}`, held.access);
    expect(response.status).toBe(200);
    const body = await response.json() as { txn: string; at: string };
    expect(body.txn).toBe(held.claims.txn);
    expect(body.at).toBeTruthy();
  });

  /**
   * One request, and the reason it is one is not convenience: five reads meant five permission
   * checks and a caller assembling evidence, which a regulator with an HTTP client cannot do.
   */
  it('assembles the whole flow in a single request', async () => {
    if (!live || !held) return;
    const response = await asHolder(`/audit/flows/${held.claims.txn}`, held.access);
    expect(response.status).toBe(200);

    const flow = await response.json() as {
      txn: string;
      events: Array<{ action: string; outcome: string }>;
      tokens: Array<{ jti: string }>;
      principal?: { displayName?: string; userName: string };
      session?: unknown;
      gone: Array<{ what: string; because: string }>;
    };

    expect(flow.txn).toBe(held.claims.txn);
    // The authorization and its redemption, which used to be two unrelated entries.
    expect(flow.events.map((event) => event.action)).toContain('authorization.code_issued');
    expect(flow.events.map((event) => event.action)).toContain('token.issued');
    // The token this investigation started from is named in its own flow.
    expect(flow.tokens.map((token) => token.jti)).toContain(held.claims.jti);
    expect(flow.session, 'the session the flow produced').toBeTruthy();
    expect(flow.principal?.userName, 'the person, read through the encrypting client').toBeTruthy();
  });

  /**
   * Absence with a reason is evidence; absence alone is a gap.
   *
   * The ticket is TTL bounded in minutes by design, so every audit after the fact finds it gone. A
   * view that simply omitted it would read as though the flow had no authorization request.
   */
  it('says what is gone and why, rather than leaving a hole', async () => {
    if (!live || !held) return;
    const flow = await (await asHolder(`/audit/flows/${held.claims.txn}`, held.access)).json() as {
      gone: Array<{ what: string; because: string }>;
    };
    const ticket = flow.gone.find((entry) => entry.what === 'authorization request');
    expect(ticket, 'the ticket must be accounted for').toBeTruthy();
    expect(ticket?.because).toMatch(/TTL/);
  });

  /**
   * The assertion that would fail silently.
   *
   * A `txn` is readable by anybody holding the token, so this endpoint must not become "paste any
   * txn and read anybody's flow". And the refusal is 404 rather than 403: a 403 would confirm that
   * the flow exists, which is exactly what somebody holding a captured identifier wants to know.
   */
  it('will not hand somebody else\'s flow to a caller with no oversight role, and says 404 not 403', async () => {
    if (!live || !held) return;
    const ordinary = await tokenFor(ORDINARY);
    if (!ordinary) return;

    const response = await asHolder(`/audit/flows/${held.claims.txn}`, ordinary.access);
    expect(response.status).toBe(404);
    // Not 403, which would confirm the flow is real.
    expect(response.status).not.toBe(403);
  });

  it('lets somebody read their OWN flow without any oversight role', async () => {
    if (!live) return;
    const ordinary = await tokenFor(ORDINARY);
    if (!ordinary) return;

    const response = await asHolder(`/audit/flows/${ordinary.claims.txn}`, ordinary.access);
    expect(response.status).toBe(200);
  });
});

describe('v41 P10: the console adds no filtering of its own', () => {
  let live = false;
  let token = '';

  beforeAll(async () => {
    try {
      await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
      live = true;
    } catch {
      return;
    }
    token = (await tokenFor(OVERSIGHT))?.access ?? '';
  });

  const query = (search: string) => fetch(`${GIAM}/api/v1/realms/${REALM}/security-events?${search}`, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(20000),
  });

  /** D47: the console paged over one fetched batch, because there was no total to page against. */
  it('reports how many match, not how many were returned', async () => {
    if (!live || !token) return;
    const body = await (await query('limit=1')).json() as { total: number; events: unknown[] };
    expect(body.events).toHaveLength(1);
    expect(body.total).toBeGreaterThan(1);
  });

  it('pages on the server, so there is something beyond the first batch', async () => {
    if (!live || !token) return;
    /**
     * Asserted as "the offset page IS the tail of the wider page", not as "the timestamps differ".
     *
     * The first version compared `ts` between pages and was flaky in a full run: events are ordered
     * by time and several are written within the same millisecond, so two pages legitimately begin
     * at the same timestamp. `ts` is an ordering key and not an identity, and a test that treats it
     * as one fails on the data rather than on the behaviour.
     */
    /**
     * Both reads are bounded by the same `to`, and that is the point rather than a workaround.
     *
     * The first two versions of this test compared two unbounded reads and were flaky in a full
     * run, for a reason that is a property of offset paging rather than a defect: the trail is
     * being WRITTEN to continuously, so events land at the top between the two requests and shift
     * everything down. Paging an unbounded, growing collection by offset cannot be stable, and a
     * caller that needs a stable page must bound it. The API documents that now.
     */
    const bound = `to=${encodeURIComponent(new Date(Date.now() - 5_000).toISOString())}`;
    const wide = await (await query(`limit=4&offset=0&${bound}`)).json() as { events: Array<Record<string, unknown>> };
    if (wide.events.length < 4) return;

    const offset = await (await query(`limit=2&offset=2&${bound}`)).json() as { events: Array<Record<string, unknown>> };
    expect(offset.events).toHaveLength(2);
    expect(offset.events).toEqual(wide.events.slice(2, 4));
  });

  /** The filters that were applied in the browser, which is a presentation choice and not a control. */
  it('filters by actor and by flow on the server', async () => {
    if (!live || !token) return;
    expect((await query('actor=person&limit=5')).status).toBe(200);
    expect((await query('txn=a-flow-that-does-not-exist')).status).toBe(200);
    const empty = await (await query('txn=a-flow-that-does-not-exist')).json() as { total: number };
    expect(empty.total).toBe(0);
  });

  /** D48: the export was assembled in the browser from whatever the screen had fetched. */
  it('produces the evidence export itself, from the query', async () => {
    if (!live || !token) return;
    const response = await query('format=csv&limit=5');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toMatch(/text\/csv/);
    const text = await response.text();
    // The filter travels in the file, so it says what it is a slice of.
    expect(text).toMatch(/^# filter:/);
    expect(text).toContain('ts,action,outcome');
  });
});
