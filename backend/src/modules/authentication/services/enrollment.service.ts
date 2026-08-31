import { Db } from 'mongodb';
import { createHmac, timingSafeEqual, createVerify, createPublicKey, randomUUID } from 'crypto';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { CredentialRecord } from '../../directory/models/credential.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { RealmRecord } from '../../realm/models/realm.model';
import { newMeta } from '../../../shared/models/base.model';
import { derivedSecret } from '../../../shared/services/secrets';

/**
 * Registering an authenticator: the ceremony that turns a key pair on a device into a credential.
 *
 * The registration challenge is STATELESS, a keyed digest over the subject and an expiry rather than
 * a row somewhere. There is no ceremony collection to grow, to expire or to clean up, and a challenge
 * that cannot be replayed after its expiry needs no storage to prove it.
 *
 * Only the PUBLIC half is ever stored. That is the property worth stating plainly: a full dump of
 * this collection lets nobody authenticate as anybody.
 */

const CHALLENGE_LIFETIME_SECONDS = 300;

export type CredentialAlgorithm = 'RS256' | 'ES256';

export interface EnrollmentFailure {
  status: number;
  error: string;
  description?: string;
}

function refuse(status: number, error: string, description?: string): EnrollmentFailure {
  return { status, error, description };
}

export function isEnrollmentFailure(value: unknown): value is EnrollmentFailure {
  return typeof value === 'object' && value !== null && 'error' in value && 'status' in value;
}

function challengeKey(): string {
  return derivedSecret('enrollment');
}

function sign(payload: { sub: string; nonce: string; exp: number }): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${createHmac('sha256', challengeKey()).update(body).digest('base64url')}`;
}

function readChallenge(challenge: string): { sub: string; nonce: string; exp: number } | EnrollmentFailure {
  const [body, mac] = challenge.split('.');
  if (!body || !mac) return refuse(400, 'invalid_request', 'malformed challenge');

  const expected = createHmac('sha256', challengeKey()).update(body).digest('base64url');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  // Length first: the comparison throws on differing lengths, and a wrong-length digest is a
  // mismatch anyway, so this keeps a malformed challenge a refusal rather than an error.
  if (a.length !== b.length || !timingSafeEqual(a, b)) return refuse(400, 'invalid_request', 'challenge signature invalid');

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now()) {
      return refuse(400, 'invalid_request', 'challenge expired');
    }
    return payload;
  } catch {
    return refuse(400, 'invalid_request', 'malformed challenge');
  }
}

export interface RegisterInput {
  challenge: string;
  publicKeyPem: string;
  algorithm: CredentialAlgorithm;
  signature: string;
  credentialId?: string;
  label?: string;
}

export interface CredentialView {
  credentialId: string;
  algorithm: CredentialAlgorithm;
  label?: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string;
}

function view(credential: CredentialRecord): CredentialView {
  return {
    credentialId: credential.credentialId,
    algorithm: credential.algorithm as CredentialAlgorithm,
    ...(credential.label ? { label: credential.label } : {}),
    status: credential.status,
    createdAt: credential.createdAt,
    ...(credential.lastUsedAt ? { lastUsedAt: credential.lastUsedAt } : {}),
  };
}

export class EnrollmentService {
  constructor(private readonly db: Db) {}

  private get credentials() {
    return this.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
  }

  private audit(realm: RealmRecord, subjectId: string, action: string, outcome: 'success' | 'failure', detail: Record<string, unknown>, cause?: string): void {
    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'credential',
      action,
      outcome,
      subjectId,
      ...(cause ? { cause } : {}),
      detail,
    });
  }

  issueChallenge(subjectId: string): { challenge: string; expiresIn: number } {
    const exp = Math.floor(Date.now() / 1000) + CHALLENGE_LIFETIME_SECONDS;
    return {
      challenge: sign({ sub: subjectId, nonce: randomUUID(), exp }),
      expiresIn: CHALLENGE_LIFETIME_SECONDS,
    };
  }

  /**
   * Registration.
   *
   * The device signs the challenge with the key it is registering, which is what makes this a
   * registration of a key somebody HOLDS rather than of a public key somebody copied.
   */
  async register(realm: RealmRecord, subjectId: string, input: RegisterInput): Promise<CredentialView | EnrollmentFailure> {
    if (input.algorithm !== 'RS256' && input.algorithm !== 'ES256') {
      return refuse(400, 'invalid_request', 'algorithm must be RS256 or ES256');
    }

    const claims = readChallenge(input.challenge);
    if (isEnrollmentFailure(claims)) return claims;
    if (claims.sub !== subjectId) return refuse(401, 'invalid_grant', 'the challenge belongs to another principal');

    let proven = false;
    try {
      const verifier = createVerify('sha256');
      verifier.update(input.challenge);
      verifier.end();
      proven = verifier.verify(
        { key: createPublicKey(input.publicKeyPem), dsaEncoding: 'ieee-p1363' },
        Buffer.from(input.signature, 'base64url'),
      );
    } catch {
      proven = false;
    }
    if (!proven) {
      this.audit(realm, subjectId, 'credential.registered', 'failure', {}, 'bad_signature');
      return refuse(401, 'invalid_grant', 'the registration proof did not verify');
    }

    const credentialId = input.credentialId ?? randomUUID();
    if (await this.credentials.findOne({ credentialId }, { projection: { _id: 0, credentialId: 1 } })) {
      return refuse(409, 'invalid_request', 'that credential id is already registered');
    }

    const now = new Date().toISOString();
    await this.credentials.insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      credentialId,
      subjectId,
      type: 'public_key',
      publicKeyPem: input.publicKeyPem,
      algorithm: input.algorithm,
      signCount: 0,
      ...(input.label ? { label: input.label } : {}),
      status: 'active',
      assurance: { level: 'aal2', method: 'public_key', verifiedAt: now },
      createdAt: now,
      meta: newMeta('Credential'),
    } as CredentialRecord);

    this.audit(realm, subjectId, 'credential.registered', 'success', { credentialId, algorithm: input.algorithm });
    const stored = await this.credentials.findOne({ credentialId }, { projection: { _id: 0 } });
    return view(stored as CredentialRecord);
  }

  async list(subjectId: string): Promise<CredentialView[]> {
    const rows = await this.credentials
      .find({ subjectId, type: 'public_key' }, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
    return rows.map(view);
  }

  /** Owner scoped, so a credential id belonging to somebody else is simply not found. */
  async revoke(realm: RealmRecord, subjectId: string, credentialId: string): Promise<true | EnrollmentFailure> {
    const result = await this.credentials.updateOne(
      { credentialId, subjectId, status: 'active' },
      { $set: { status: 'revoked', 'meta.lastModified': new Date().toISOString() } },
    );
    if (result.matchedCount === 0) return refuse(404, 'invalid_request', 'no such credential');
    this.audit(realm, subjectId, 'credential.revoked', 'success', { credentialId });
    return true;
  }

  /**
   * Rotation: register the replacement first, then retire the old one.
   *
   * In that order deliberately. The reverse leaves a person with no authenticator whenever the
   * registration then fails, which is exactly when they need one to recover.
   */
  async rotate(realm: RealmRecord, subjectId: string, credentialId: string, input: RegisterInput): Promise<CredentialView | EnrollmentFailure> {
    const existing = await this.credentials.findOne(
      { credentialId, subjectId, status: 'active' },
      { projection: { _id: 0, credentialId: 1 } },
    );
    if (!existing) return refuse(404, 'invalid_request', 'no such credential');

    const replacement = await this.register(realm, subjectId, input);
    if (isEnrollmentFailure(replacement)) return replacement;

    await this.revoke(realm, subjectId, credentialId);
    this.audit(realm, subjectId, 'credential.rotated', 'success', {
      replaced: credentialId,
      credentialId: replacement.credentialId,
    });
    return replacement;
  }
}
