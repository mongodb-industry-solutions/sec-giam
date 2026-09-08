/**
 * v43: an administrator's unified view of a principal's credentials, and retiring one on their
 * behalf.
 *
 * `oauth_client` is a `CredentialType`, same collection as `password` and `public_key` (ADR-001):
 * this endpoint reads that collection whole, not a separate registry, and DELETE on the credential
 * itself only ever touches an authenticator, naming the right tool when asked to touch anything else.
 *
 * Skipped unless the authority is listening.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { randomUUID, generateKeyPairSync, createSign } from 'crypto';
import { tokenFor as runFlow } from './support/authorizationFlow';

const GIAM = process.env.GIAM_BASE_URL ?? 'http://127.0.0.1:8085';
const DEMO_PASSWORD = 'demo-password';
const PLATFORM = { clientId: 'giam-console', redirectUri: 'http://localhost:8086/auth/callback' };

async function reachable(): Promise<boolean> {
  try {
    await fetch(`${GIAM}/health`, { signal: AbortSignal.timeout(3000) });
    return true;
  } catch {
    return false;
  }
}

async function enrollAuthenticator(holderToken: string): Promise<string> {
  const holderHeaders = { authorization: `Bearer ${holderToken}` };
  const challengeRes = await fetch(`${GIAM}/realms/leafypay/credentials/challenge`, {
    method: 'POST', headers: holderHeaders, signal: AbortSignal.timeout(20000),
  });
  const { challenge } = await challengeRes.json() as { challenge: string };

  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signer = createSign('sha256');
  signer.update(challenge);
  signer.end();
  const signature = signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');

  const registered = await fetch(`${GIAM}/realms/leafypay/credentials`, {
    method: 'POST', headers: { ...holderHeaders, 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge, signature, algorithm: 'ES256',
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      label: 'v43 oversight test device',
    }),
    signal: AbortSignal.timeout(20000),
  });
  return (await registered.json() as { credentialId: string }).credentialId;
}

describe('v43: unified credential oversight, and retiring an authenticator on a principal\'s behalf', () => {
  let live = false;
  let managerToken = '';

  beforeAll(async () => {
    live = await reachable();
    if (live) managerToken = await runFlow(GIAM, 'leafypay', 'alex.rivera', 'demo-password', { client: PLATFORM });
  });

  async function freshHolder(): Promise<{ subjectId: string; token: string }> {
    const headers = { authorization: `Bearer ${managerToken}`, 'content-type': 'application/json' };
    const userName = `v43-cred-${randomUUID().slice(0, 8)}`;
    const registered = await fetch(`${GIAM}/realms/leafypay/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userName, password: 'Correct-Horse-1' }),
      signal: AbortSignal.timeout(20000),
    });
    const holder = await registered.json() as { subjectId: string };
    await fetch(`${GIAM}/realms/leafypay/scim/v2/Users/${holder.subjectId}`, {
      method: 'PATCH', headers,
      body: JSON.stringify({ schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', value: { active: true } }] }),
      signal: AbortSignal.timeout(20000),
    });
    const token = await runFlow(GIAM, 'leafypay', userName, 'Correct-Horse-1', { client: PLATFORM });
    return { subjectId: holder.subjectId, token };
  }

  it('lists every credential type a principal holds, password and authenticator alike, in one place', async () => {
    if (!live) return;
    const holder = await freshHolder();
    const credentialId = await enrollAuthenticator(holder.token);

    const headers = { authorization: `Bearer ${managerToken}` };
    const list = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials`, { headers, signal: AbortSignal.timeout(20000) });
    expect(list.status).toBe(200);
    const body = await list.json() as { credentials: Array<{ credentialId: string; type: string; createdAt: string }> };

    const password = body.credentials.find((c) => c.type === 'password');
    const authenticator = body.credentials.find((c) => c.credentialId === credentialId);
    expect(password, 'the password credential created at registration should be listed').toBeTruthy();
    expect(password?.createdAt, 'createdAt must be a real timestamp, not dropped').toBeTruthy();
    expect(authenticator?.type).toBe('public_key');
  });

  it('retires a lost authenticator on the principal\'s behalf, without touching anything else they hold', async () => {
    if (!live) return;
    const holder = await freshHolder();
    const credentialId = await enrollAuthenticator(holder.token);
    const headers = { authorization: `Bearer ${managerToken}` };

    const revoked = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials/${credentialId}`, {
      method: 'DELETE', headers, signal: AbortSignal.timeout(20000),
    });
    expect(revoked.status).toBe(200);
    expect((await revoked.json()).status).toBe('revoked');

    const list = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials`, { headers, signal: AbortSignal.timeout(20000) });
    const body = await list.json() as { credentials: Array<{ credentialId: string; type: string; status: string }> };
    const authenticator = body.credentials.find((c) => c.credentialId === credentialId);
    expect(authenticator?.status).toBe('revoked');
    expect(body.credentials.find((c) => c.type === 'password')?.status).toBe('active');
  });

  it('refuses to retire a password this way, naming the reset route instead', async () => {
    if (!live) return;
    const holder = await freshHolder();
    const headers = { authorization: `Bearer ${managerToken}` };

    const list = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials`, { headers, signal: AbortSignal.timeout(20000) });
    const password = (await list.json() as { credentials: Array<{ credentialId: string; type: string }> })
      .credentials.find((c) => c.type === 'password')!;

    const attempt = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials/${password.credentialId}`, {
      method: 'DELETE', headers, signal: AbortSignal.timeout(20000),
    });
    expect(attempt.status).toBe(400);
    expect((await attempt.json()).detail).toContain('reset');
  });

  it('refuses a credential id that does not exist for this principal', async () => {
    if (!live) return;
    const holder = await freshHolder();
    const headers = { authorization: `Bearer ${managerToken}` };
    const attempt = await fetch(`${GIAM}/realms/leafypay/identities/${holder.subjectId}/credentials/no-such-credential`, {
      method: 'DELETE', headers, signal: AbortSignal.timeout(20000),
    });
    expect(attempt.status).toBe(404);
  });
});
