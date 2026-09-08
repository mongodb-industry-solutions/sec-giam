import { Db } from 'mongodb';
import type { KeyProvider } from '../../../shared/ports';
import { keyProviders } from '../../../shared/ports';
import { KeyRecord } from '../models/key.model';
import { KeyRing } from './keyRing.service';
import { MongoSigningKeyStore } from './signingKeyStore';
import { config } from '../../../config';

/**
 * Reading and changing the realm's key set, without ever touching private material.
 *
 * There is nothing here to withhold, and that is a property of the design rather than of a
 * projection: the private half never reaches the database. What this adds over reading the
 * collection is the interpretation, which is the part an operator actually needs. A key can be
 * signing, or lapsed but still published so tokens it already signed verify, or past its grace and
 * carried only as history. Those three read identically as `status` plus two timestamps, and telling
 * them apart is the whole job of a key screen.
 */

export type KeyPhase = 'signing' | 'published' | 'retired' | 'revoked';

export interface KeyView {
  kid: string;
  keyId: string;
  algorithm: KeyRecord['alg'];
  use: KeyRecord['use'];
  keySize?: number;
  provider: KeyRecord['provider'];
  status: KeyRecord['status'];
  phase: KeyPhase;
  /** What the phase means, in a sentence, so the screen does not have to encode the rules again. */
  phaseReason: string;
  /** Which replica holds the private half. Absent when custody is external to this deployment. */
  instanceId?: string;
  /** True when this process is the replica that holds it. */
  ownedByThisInstance: boolean;
  externalCustody: boolean;
  leaseExpiresAt?: string;
  leaseLapsed: boolean;
  signingEligible: boolean;
  notBefore: string;
  /** When it stops being published. Until then a verifier still accepts what it signed. */
  notAfter?: string;
  rotatedAt?: string;
}

export interface KeySetView {
  keys: KeyView[];
  /** The custody mode in force, so the screen can explain why a control is offered or not. */
  provider: string;
  externalCustody: boolean;
  rotatable: boolean;
  /** This process's identity, so "yours" is answerable in the list. */
  instanceId: string;
  leaseSeconds: number;
  publicationGraceSeconds: number;
}

export type KeyRefusal = { status: number; title: string; detail: string };

export function isKeyRefusal(value: unknown): value is KeyRefusal {
  return typeof value === 'object' && value !== null && 'status' in value && 'title' in value;
}

export class KeyAdminService {
  private readonly store: MongoSigningKeyStore;

  constructor(
    private readonly db: Db,
    private readonly provider: KeyProvider = keyProviders.resolve(config.keys.provider),
  ) {
    this.store = new MongoSigningKeyStore(this.db);
  }

  private ring(): KeyRing {
    return new KeyRing(this.store, this.provider);
  }

  private view(record: KeyRecord, now: number): KeyView {
    const leaseLapsed = Boolean(record.leaseExpiresAt && Date.parse(record.leaseExpiresAt) <= now);
    const stillPublished = !record.notAfter || Date.parse(record.notAfter) > now;

    let phase: KeyPhase = 'retired';
    let phaseReason = 'Past its publication window. Every token it signed has expired, so it is history.';
    if (record.status === 'revoked') {
      phase = 'revoked';
      phaseReason = 'Withdrawn from the key set. Anything it signed no longer verifies.';
    } else if (record.status === 'active' && record.signingEligible && !leaseLapsed) {
      phase = 'signing';
      phaseReason = 'Offered for signing by the replica that holds it, and published for verification.';
    } else if (record.status === 'active' && stillPublished) {
      phase = 'published';
      phaseReason =
        'No longer offered for signing, still published so tokens already signed with it keep '
        + 'verifying until the grace period ends.';
    }

    return {
      kid: record.kid,
      keyId: record.keyId,
      algorithm: record.alg,
      use: record.use,
      ...(record.keySize ? { keySize: record.keySize } : {}),
      provider: record.provider,
      status: record.status,
      phase,
      phaseReason,
      ...(record.instanceId ? { instanceId: record.instanceId } : {}),
      ownedByThisInstance: record.instanceId === config.keys.instanceId,
      externalCustody: !record.instanceId,
      ...(record.leaseExpiresAt ? { leaseExpiresAt: record.leaseExpiresAt } : {}),
      leaseLapsed,
      signingEligible: record.signingEligible,
      notBefore: record.notBefore,
      ...(record.notAfter ? { notAfter: record.notAfter } : {}),
      ...(record.rotatedAt ? { rotatedAt: record.rotatedAt } : {}),
    };
  }

  /**
   * The realm's whole key set, newest first.
   *
   * The union across replicas, not this replica's key: that union is what a verifier resolves a kid
   * against, so showing anything narrower would show a set nobody actually uses.
   */
  async list(realmId: string): Promise<KeySetView> {
    const records = await this.store.listByRealm(realmId);
    const now = Date.now();
    return {
      keys: records
        .map((record) => this.view(record, now))
        .sort((a, b) => Date.parse(b.notBefore) - Date.parse(a.notBefore)),
      provider: this.provider.name,
      externalCustody: this.provider.externalCustody,
      rotatable: typeof this.provider.rotate === 'function',
      instanceId: config.keys.instanceId,
      leaseSeconds: config.keys.leaseSeconds,
      publicationGraceSeconds: config.keys.publicationGraceSeconds,
    };
  }

  /**
   * Replaces this replica's key with a fresh pair.
   *
   * The outgoing key is NOT unpublished. It stops signing and stays in the key set for the grace
   * period, because every token it already signed must still verify: rotation that invalidated live
   * sessions would be an outage rather than a hygiene measure.
   */
  async rotate(realmId: string, tenantId: string): Promise<{ kid: string; previousKid?: string; previousPublishedUntil?: string } | KeyRefusal> {
    if (typeof this.provider.rotate !== 'function') {
      return {
        status: 409,
        title: 'Rotation is not this provider\'s to perform',
        detail:
          `Custody is held by the ${this.provider.name} provider, outside this process. Rotate the key `
          + 'where it lives; doing it here would leave the two out of step.',
      };
    }

    const previousKid = await this.provider.ensureKey(realmId).catch(() => undefined);
    const kid = await this.ring().rotate(realmId, tenantId);

    let previousPublishedUntil: string | undefined;
    if (previousKid && previousKid !== kid) {
      const retired = await this.store.findByKid(previousKid);
      previousPublishedUntil = retired?.notAfter;
    }

    return {
      kid,
      ...(previousKid && previousKid !== kid ? { previousKid } : {}),
      ...(previousPublishedUntil ? { previousPublishedUntil } : {}),
    };
  }

  /**
   * Stops publishing a key now.
   *
   * Irreversible in the way that matters: a verifier that can no longer resolve the kid rejects
   * every token signed with it, including ones a person is holding right now. That is exactly the
   * right action for a key believed compromised and exactly the wrong one for tidiness, so the
   * caller has to say which it is when the key is still inside its publication window.
   */
  async retire(
    realmId: string,
    kid: string,
    options: { acknowledged: boolean },
  ): Promise<{ kid: string; warning?: string } | KeyRefusal | null> {
    const record = await this.store.findByKid(kid);
    if (!record || record.realmId !== realmId) return null;

    if (record.status !== 'active') {
      return { status: 409, title: 'Already out of the key set', detail: `That key is ${record.status}, so it is not published.` };
    }

    const now = Date.now();
    const stillPublished = !record.notAfter || Date.parse(record.notAfter) > now;
    const warning = stillPublished
      ? 'This key is still published. Tokens already signed with it stop verifying the moment it is '
        + 'withdrawn, so anybody holding one is signed out at their next request.'
      : undefined;

    if (stillPublished && !options.acknowledged) {
      return { status: 409, title: 'Live tokens depend on this key', detail: warning as string };
    }

    await this.store.upsert({
      ...record,
      status: 'deprecated',
      signingEligible: false,
      notAfter: new Date(now).toISOString(),
    });

    return { kid, ...(warning ? { warning } : {}) };
  }
}
