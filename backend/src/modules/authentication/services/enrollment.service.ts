import { Db } from 'mongodb';
import { createHmac, timingSafeEqual, createVerify, createPublicKey, randomUUID } from 'crypto';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { CredentialRecord } from '../../directory/models/credential.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { SignalDispatcher } from '../../authorization/services/signalDispatcher';
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

  private audit(realm: RealmRecord, subjectId: string | undefined, action: string, outcome: 'success' | 'failure', detail: Record<string, unknown>, cause?: string): void {
    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'credential',
      action,
      outcome,
      // Absent for the break-glass operator credential, which is nobody in particular.
      ...(subjectId ? { subjectId } : {}),
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
      this.audit(realm, subjectId, 'credential.registered', 'failure', { algorithm: input.algorithm }, 'unsupported_algorithm');
      return refuse(400, 'invalid_request', 'algorithm must be RS256 or ES256');
    }

    const claims = readChallenge(input.challenge);
    if (isEnrollmentFailure(claims)) {
      // A malformed, forged or expired challenge. Recorded because a stream of them against one
      // account is somebody working on the ceremony rather than a person mistyping.
      this.audit(realm, subjectId, 'credential.registered', 'failure', {}, 'bad_challenge');
      return claims;
    }
    if (claims.sub !== subjectId) {
      this.audit(realm, subjectId, 'credential.registered', 'failure', {}, 'challenge_belongs_to_another_principal');
      return refuse(401, 'invalid_grant', 'the challenge belongs to another principal');
    }

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
      this.audit(realm, subjectId, 'credential.registered', 'failure', { credentialId }, 'credential_id_taken');
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

  /**
   * Owner scoped, so a credential id belonging to somebody else is simply not found, UNLESS `actor`
   * names an administrator revoking it on the owner's behalf (a lost device, during an incident).
   *
   * `actor` is who the audit trail credits: absent, this is the owner acting on their own credential
   * as before; present, the acting administrator is the accountable party and the owner is recorded
   * as the target, exactly the actor/target split every other administrative act in this authority
   * already keeps.
   */
  async revoke(
    realm: RealmRecord, subjectId: string, credentialId: string, actor?: { subjectId?: string },
  ): Promise<true | EnrollmentFailure> {
    // `actor` being PASSED marks this as administrator mediated, even when its own `subjectId` is
    // absent (the break-glass operator credential, accountable to nobody in particular). Falling
    // back to the owner in that case would misattribute the act to the very person it was done to.
    const attributedTo = actor ? actor.subjectId : subjectId;
    const result = await this.credentials.updateOne(
      { credentialId, subjectId, status: 'active' },
      { $set: { status: 'revoked', 'meta.lastModified': new Date().toISOString() } },
    );
    if (result.matchedCount === 0) {
      // Owner scoped, so this is either a credential that is gone or one that belongs to somebody
      // else. Both are worth a line against the caller who asked.
      this.audit(
        realm, attributedTo, 'credential.revoked', 'failure',
        { credentialId, ...(actor ? { ownerSubjectId: subjectId } : {}) }, 'no_such_credential',
      );
      return refuse(404, 'invalid_request', 'no such credential');
    }
    this.audit(
      realm, attributedTo, 'credential.revoked', 'success',
      { credentialId, ...(actor ? { ownerSubjectId: subjectId } : {}) },
    );

    /**
     * A receiver subscribed to `credential-change` is told, rather than left to poll.
     *
     * This is the signal a resource server needs to stop trusting a step-up it already saw: the
     * session may well still be live, because losing an authenticator is not signing out, and
     * nothing else would tell a third party that the factor behind it is gone.
     *
     * Not awaited. Revoking the credential has already succeeded and is already durable, so a
     * receiver being slow must not hold the caller.
     */
    void new SignalDispatcher(this.db).dispatch({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      event: 'credential-change',
      subjectId,
      reason: actor ? 'the credential was revoked by an administrator' : 'the credential was revoked by its owner',
      category: 'credential',
      target: { type: 'credential', ref: credentialId },
    });
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
    if (!existing) {
      this.audit(realm, subjectId, 'credential.rotated', 'failure', { credentialId }, 'no_such_credential');
      return refuse(404, 'invalid_request', 'no such credential');
    }

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
