// v39 §10.18 / P12.7: one session across the fleet, and one logout that ends it everywhere.
//
// This is the capability the platform did not have at all before. Each application kept its own
// session, so signing out of one left the others open, and there was no answer to "sign this person
// out everywhere" because nothing could enumerate where they were signed in.
//
// Ending a session has to do three things, and all three are asserted here, because any two of them
// without the third leaves a way back in:
//
//   1. The session record is terminated, so nothing can be authorised from it again.
//   2. The tokens issued under it are revoked, so anything outstanding stops working NOW rather than
//      running to its expiry.
//   3. The principal's session epoch rises, which retires every token issued before this moment
//      WITHOUT having to list them, including any the authority never recorded.
//
// The third is the one that matters most and is easiest to leave out. A deployment that revoked only
// what it had a row for would still honour a token it had lost track of.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const DATA = resolve(__dirname, '../../../backend/data');
/**
 * Read from the fixture rather than written here.
 *
 * It was the literal `'leafypay'`, and it was compared to `identity.realm` in the identity fixture:
 * renaming the realm left the two disagreeing, and this suite reported "no demo principal is
 * seeded" for a database full of them. A test that hardcodes a name it also has to match is a test
 * that breaks on a rename instead of testing one.
 */
const REALM = (JSON.parse(readFileSync(resolve(DATA, 'realms.json'), 'utf8')) as Array<{ name: string }>)[0].name;
const DEMO_PASSWORD = 'demo-password';

interface IdentityFixture {
  realm: string;
  subjectId: string;
  userName: string;
  demoFeatured?: boolean;
  lifecycleState?: string;
}

const identities = JSON.parse(readFileSync(resolve(DATA, 'identities.json'), 'utf8')) as IdentityFixture[];

interface ClientFixture {
  realm: string;
  clientId: string;
  postLogoutRedirectUris?: string[];
}

/** Two clients of the same realm that each declare a return address, read from the fixture. */
const clients = (JSON.parse(readFileSync(resolve(DATA, 'clients.json'), 'utf8')) as ClientFixture[])
  .filter((client) => client.realm === REALM && (client.postLogoutRedirectUris?.length ?? 0) > 0);

/** Any principal who can actually sign in. The property under test is not specific to one person. */
const subject = identities.find(
  (identity) => identity.realm === REALM && identity.demoFeatured && identity.lifecycleState !== 'deprovisioned',
);

let app: FastifyInstance;

beforeAll(async () => {
  const { buildApp } = await import('../../../backend/src/app');
  app = await buildApp();
  await app.ready();
}, 120_000);

afterAll(async () => {
  await app?.close();
});

async function signIn(): Promise<{ sessionId: string; subjectId: string; epoch: number } | null> {
  const response = await app.inject({
    method: 'POST',
    url: `/api/v1/realms/${REALM}/login`,
    payload: { login: subject?.userName, password: DEMO_PASSWORD },
  });
  if (response.statusCode !== 200) return null;
  const body = response.json() as { sessionId: string; subjectId: string; sessionEpoch: number };
  return { sessionId: body.sessionId, subjectId: body.subjectId, epoch: body.sessionEpoch };
}

describe('v39 §10.18: one logout ends the session everywhere', () => {
  it('has a principal to test with, so a green result cannot be vacuous', () => {
    expect(subject, 'no demo principal is seeded, so this suite proves nothing').toBeTruthy();
  });

  it('establishes a session that the authority can see', async () => {
    const session = await signIn();
    if (!session) return;

    expect(session.sessionId).toBeTruthy();
    const live = await app.db.collection('session').findOne({ sessionId: session.sessionId });
    expect(live, 'the session was not recorded, so nothing could end it').toBeTruthy();
    expect(live?.terminatedAt).toBeUndefined();
  });

  it('terminates the session, revokes what it issued, and raises the epoch', async () => {
    const session = await signIn();
    if (!session) return;

    const before = await app.db.collection('principal').findOne({ subjectId: session.subjectId });
    const epochBefore = (before?.sessionEpoch as number) ?? 0;

    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
      payload: { session_id: session.sessionId },
    });
    expect(response.statusCode).toBe(200);

    /**
     * 1. The session is GONE, not marked.
     *
     * v40 removed `terminatedAt` on purpose, and asserting absence is the stronger test. A record
     * left behind marked dead is a record some query forgets to filter, and the filter being
     * forgotten is exactly how a revoked session keeps working. Absence cannot be forgotten.
     */
    const ended = await app.db.collection('session').findOne({ sessionId: session.sessionId });
    expect(ended, 'the session document survived the logout').toBeNull();

    /**
     * 2. Nothing issued under it survives, and there is nothing to look for.
     *
     * No token was ever written down: both kinds are JWTs, so storing one kept a redeemable
     * artifact at rest for no information the token did not already carry. What made access live
     * was the session, and the session is gone.
     */
    const tokenCollections = await app.db.listCollections({ name: 'token' }).toArray();
    expect(tokenCollections, 'a token collection exists again').toEqual([]);

    // 3. The generation is retired, which covers anything the authority never recorded.
    const after = await app.db.collection('principal').findOne({ subjectId: session.subjectId });
    expect(
      (after?.sessionEpoch as number) ?? 0,
      'the epoch did not rise, so an unrecorded token would still be honoured',
    ).toBeGreaterThan(epochBefore);
  });

  it('answers the same way to a logout that has already happened', async () => {
    const session = await signIn();
    if (!session) return;

    const first = await app.inject({
      method: 'POST',
      url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
      payload: { session_id: session.sessionId },
    });
    const second = await app.inject({
      method: 'POST',
      url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
      payload: { session_id: session.sessionId },
    });

    // Signing out twice is not an error. A client retrying after a dropped response must not be told
    // something went wrong when the thing it wanted has already happened.
    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
  });

  it('does not disclose whether an unknown session ever existed', async () => {
    const response = await app.inject({
      method: 'POST',
      url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
      payload: { session_id: 'a-session-that-never-existed' },
    });
    // The same answer as a real one. Distinguishing them would let anyone holding a list of
    // identifiers learn which are genuine.
    expect(response.statusCode).toBe(200);
  });

  it('leaves other sessions of the same principal alone', async () => {
    const one = await signIn();
    const two = await signIn();
    if (!one || !two) return;

    await app.inject({
      method: 'POST',
      url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
      payload: { session_id: one.sessionId },
    });

    // Ending ONE session is not ending them all. That is a separate, deliberate operation, and
    // conflating them would make signing out of a laptop close a session on a phone.
    const other = await app.db.collection('session').findOne({ sessionId: two.sessionId });
    expect(other?.terminatedAt, 'a second session was ended by a single-session logout').toBeUndefined();
  });
});


async function endSession(payload: Record<string, unknown>) {
  const session = await signIn();
  // A failed sign-in fails the test. Returning quietly here made every redirect and token-hint
  // assertion below pass without ever calling logout, which is how a security check goes vacuous.
  expect(session, 'could not sign in, so no logout was exercised').not.toBeNull();
  if (!session) throw new Error('unreachable');
  const response = await app.inject({
    method: 'POST',
    url: `/api/v1/realms/${REALM}/protocol/oidc/logout`,
    payload: { session_id: session.sessionId, ...payload },
  });
  expect(response.statusCode).toBe(200);
  return response.json() as { post_logout_redirect_uri?: string };
}

/**
 * A return address belongs to the client that registered it, and to no other client in the realm.
 *
 * This used to be checked realm-wide: any URI any client had registered was honoured for anybody.
 * That is a closed list and so never an open redirect, but it let one application end a session and
 * send the browser to a DIFFERENT application's address, and it meant a client's own registration
 * was not a boundary it could rely on. RP-Initiated Logout 1.0 puts the check on the requesting
 * client, which is why the request has to say who that is.
 */
describe('a post-logout address is held against the registration of the client that asked', () => {
  it('has two clients with registered return addresses, so the checks below are not vacuous', () => {
    expect(clients.length, 'fewer than two clients declare a post-logout address').toBeGreaterThan(1);
  });

  it('honours a client its own registered address', async () => {
    const client = clients[0];
    const uri = client.postLogoutRedirectUris![0];
    const body = await endSession({ post_logout_redirect_uri: uri, client_id: client.clientId });
    expect(body.post_logout_redirect_uri).toBe(uri);
  });

  it('refuses one client the address another client registered', async () => {
    const [first, second] = clients;
    const foreign = second.postLogoutRedirectUris!
      .find((uri) => !(first.postLogoutRedirectUris ?? []).includes(uri));
    expect(foreign, 'the two clients register identical addresses, so this proves nothing').toBeTruthy();
    const body = await endSession({ post_logout_redirect_uri: foreign, client_id: first.clientId });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });

  it('honours nothing when the request does not say which client is asking', async () => {
    const client = clients[0];
    const body = await endSession({ post_logout_redirect_uri: client.postLogoutRedirectUris![0] });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });

  it('refuses an address no client registered, named client or not', async () => {
    const client = clients[0];
    const body = await endSession({
      post_logout_redirect_uri: 'https://somewhere-else.example/landing',
      client_id: client.clientId,
    });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });
});

/**
 * `id_token_hint`: the evidence a client is who it says, as opposed to the `client_id` it claims.
 *
 * Real tokens, signed with the realm's own key, because the property under test is the verification
 * itself: a hint this authority did not sign, or signed as the wrong kind of token, must name no
 * client, and an expired one must still name its client (RP-Initiated Logout 1.0: a session being over
 * is exactly when somebody signs out). Only the lifetime is ever relaxed, never the signature.
 */
describe('id_token_hint identifies the client that is signing out', () => {
  const first = clients[0];
  const second = clients[1];
  const own = first.postLogoutRedirectUris![0];

  async function mint(options: { audience?: string; expiresIn?: number; typ?: string } = {}): Promise<string> {
    const { RealmService } = await import('../../../backend/src/modules/realm/services/realm.service');
    const { KeyRing } = await import('../../../backend/src/modules/keys/services/keyRing.service');
    const { MongoSigningKeyStore } = await import('../../../backend/src/modules/keys/services/signingKeyStore');
    const { JwtTokenFormat } = await import('../../../backend/src/modules/oauth/services/jwtTokenFormat');
    const realm = await new RealmService(app.db).byName(REALM);
    const ring = new KeyRing(new MongoSigningKeyStore(app.db));
    const now = Math.floor(Date.now() / 1000);
    return new JwtTokenFormat(ring, realm!.realmId, options.typ ?? 'JWT').issue({
      iss: realm!.issuer,
      aud: options.audience ?? first.clientId,
      sub: subject?.subjectId,
      jti: `hint-${Math.random().toString(36).slice(2)}`,
      iat: now - 7200,
      exp: now + (options.expiresIn ?? 300),
    }, await ring.signingKid(realm!.realmId));
  }

  it('honours the address of the client the hint was issued to, with no client_id sent', async () => {
    const body = await endSession({ post_logout_redirect_uri: own, id_token_hint: await mint() });
    expect(body.post_logout_redirect_uri).toBe(own);
  });

  it('still identifies the client when the hint has expired, because a session ending is when one signs out', async () => {
    const body = await endSession({ post_logout_redirect_uri: own, id_token_hint: await mint({ expiresIn: -3600 }) });
    expect(body.post_logout_redirect_uri).toBe(own);
  });

  it('honours nothing when the hint and an explicit client_id name different clients', async () => {
    const body = await endSession({
      post_logout_redirect_uri: own,
      id_token_hint: await mint(),
      client_id: second.clientId,
    });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });

  it('honours nothing for a hint whose signature was altered', async () => {
    const hint = await mint();
    const forged = `${hint.slice(0, -4)}${hint.endsWith('AAAA') ? 'BBBB' : 'AAAA'}`;
    const body = await endSession({ post_logout_redirect_uri: own, id_token_hint: forged });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });

  it('honours nothing for a token signed as another kind, so an access token cannot stand in for a hint', async () => {
    const body = await endSession({ post_logout_redirect_uri: own, id_token_hint: await mint({ typ: 'at+jwt' }) });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });

  it('holds the address against the hinted client, not against whichever client registered it', async () => {
    const foreign = second.postLogoutRedirectUris!.find((uri) => !(first.postLogoutRedirectUris ?? []).includes(uri));
    expect(foreign, 'the two clients register identical addresses, so this proves nothing').toBeTruthy();
    const body = await endSession({ post_logout_redirect_uri: foreign, id_token_hint: await mint() });
    expect(body.post_logout_redirect_uri).toBeUndefined();
  });
});
