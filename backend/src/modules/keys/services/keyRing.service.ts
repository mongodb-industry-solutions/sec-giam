import { createPublicKey } from 'crypto';
import type { KeyProvider } from '../../../shared/ports';
import { keyProviders } from '../../../shared/ports';
import { SigningKeyRecord, JwkSet, assertNoPlaintextPrivateKey } from '../models/signingKey.model';
import { pemToJwk } from './jwk';
import { newMeta, DEFAULT_TENANT_ID } from '../../../shared/models/base.model';
import { config } from '../../../config';

/**
 * Where published keys live. The database is the coordination point, and it is already there: no new
 * infrastructure, no shared volume, no key-encryption key to distribute and later lose.
 */
export interface SigningKeyStore {
  upsert(record: SigningKeyRecord): Promise<void>;
  findByKid(kid: string): Promise<SigningKeyRecord | null>;
  listByRealm(realmId: string): Promise<SigningKeyRecord[]>;
  renewLease(kid: string, leaseExpiresAt: string): Promise<void>;
  markIneligible(kid: string, notAfter: string): Promise<void>;
}

export class InMemorySigningKeyStore implements SigningKeyStore {
  readonly records = new Map<string, SigningKeyRecord>();

  async upsert(record: SigningKeyRecord) {
    this.records.set(record.kid, { ...this.records.get(record.kid), ...record });
  }

  async findByKid(kid: string) {
    return this.records.get(kid) ?? null;
  }

  async listByRealm(realmId: string) {
    return [...this.records.values()].filter((record) => record.realmId === realmId);
  }

  async renewLease(kid: string, leaseExpiresAt: string) {
    const record = this.records.get(kid);
    if (record) this.records.set(kid, { ...record, leaseExpiresAt, signingEligible: true });
  }

  async markIneligible(kid: string, notAfter: string) {
    const record = this.records.get(kid);
    if (record) this.records.set(kid, { ...record, signingEligible: false, notAfter });
  }
}

/**
 * The realm's key set, and this replica's place in it.
 *
 * Two rules make more than one replica correct, and both are here rather than in a provider, because
 * they hold whatever the custody mode is.
 *
 * Leases, not liveness assumptions. A replica renews its lease on a heartbeat. When the lease lapses
 * the key stops being offered for SIGNING but stays PUBLISHED for a grace period at least as long as
 * the maximum token lifetime, because tokens it already signed must still verify. Removing it sooner
 * would invalidate live sessions on a scale-down, which is the failure the grace exists to prevent.
 *
 * Scale-up needs nothing: a new replica's kid is unknown to a cached verifier, and the rate-limited
 * refetch on an unknown kid, written for rotation, is exactly what makes elastic scaling work.
 */
export class KeyRing {
  constructor(
    private readonly store: SigningKeyStore,
    private readonly provider: KeyProvider = keyProviders.resolve(config.keys.provider),
    private readonly clock: () => Date = () => new Date(),
  ) {}

  private leaseUntil(): string {
    return new Date(this.clock().getTime() + config.keys.leaseSeconds * 1000).toISOString();
  }

  /** Registers this replica's public key in the realm's set, and claims a lease on it. */
  async publishOwnKey(realmId: string, tenantId: string = DEFAULT_TENANT_ID): Promise<string> {
    const kid = await this.provider.ensureKey(realmId);
    const publicKeyPem = await this.provider.publicKeyPem(kid);
    const now = this.clock().toISOString();

    const record: SigningKeyRecord = {
      realmId,
      tenantId,
      keyId: `key-${kid.slice(0, 16)}`,
      kid,
      alg: 'RS256',
      use: 'sig',
      publicKeyPem,
      keySize: (createPublicKey(publicKeyPem).asymmetricKeyDetails?.modulusLength) ?? undefined,
      status: 'active',
      provider: this.provider.name as SigningKeyRecord['provider'],
      // Only the modes with node custody claim an instance: a KMS key belongs to no replica.
      ...(this.provider.externalCustody ? {} : { instanceId: config.keys.instanceId }),
      leaseExpiresAt: this.leaseUntil(),
      signingEligible: true,
      notBefore: now,
      meta: newMeta('SigningKey', this.clock()),
    };

    // Public material only. Enforced here as well as in validation, because this is the write path.
    assertNoPlaintextPrivateKey(record);
    await this.store.upsert(record);
    return kid;
  }

  async renewLease(kid: string): Promise<void> {
    await this.store.renewLease(kid, this.leaseUntil());
  }

  /**
   * Retires the keys whose owning replica has gone away, without removing them from the set.
   *
   * A lapsed lease means the replica is gone, not that its tokens are. The key stops signing now and
   * stops being published only after the grace period.
   */
  async reconcileLeases(realmId: string): Promise<{ retired: string[]; unpublished: string[] }> {
    const now = this.clock().getTime();
    const grace = config.keys.publicationGraceSeconds * 1000;
    const retired: string[] = [];
    const unpublished: string[] = [];

    for (const record of await this.store.listByRealm(realmId)) {
      const lease = record.leaseExpiresAt ? Date.parse(record.leaseExpiresAt) : null;
      if (lease !== null && lease < now && record.signingEligible) {
        await this.store.markIneligible(record.kid, new Date(lease + grace).toISOString());
        retired.push(record.kid);
        continue;
      }
      const notAfter = record.notAfter ? Date.parse(record.notAfter) : null;
      if (notAfter !== null && notAfter < now && record.status === 'active') {
        // Past the grace: every token it signed has expired, so it can leave the published set.
        await this.store.upsert({ ...record, status: 'deprecated' });
        unpublished.push(record.kid);
      }
    }
    return { retired, unpublished };
  }

  /**
   * The realm's published key set: every key still trusted for verification, from ANY replica.
   *
   * The union is what makes the design work. A verifier resolves a kid against this set, so a token
   * signed by one replica verifies at another, and at every resource server, with no shared secret.
   */
  async publishedKeySet(realmId: string): Promise<JwkSet> {
    const now = this.clock().getTime();
    const records = await this.store.listByRealm(realmId);
    const keys = records
      .filter((record) => record.status !== 'revoked')
      .filter((record) => record.status === 'active')
      .filter((record) => !record.notAfter || Date.parse(record.notAfter) > now)
      .map((record) => pemToJwk(record.publicKeyPem, record.kid, record.alg));
    return { keys };
  }

  /** The key this replica may sign with right now. */
  async signingKid(realmId: string): Promise<string> {
    const kid = await this.provider.ensureKey(realmId);
    const record = await this.store.findByKid(kid);
    if (!record || !record.signingEligible || record.status !== 'active') {
      // Republish rather than fail: a lapsed lease on a replica that is plainly alive means the
      // heartbeat missed, and refusing to sign would take the replica out of service for a clock.
      await this.publishOwnKey(realmId, record?.tenantId ?? DEFAULT_TENANT_ID);
    }
    return kid;
  }

  async sign(realmId: string, payload: Buffer): Promise<{ kid: string; signature: Buffer }> {
    const kid = await this.signingKid(realmId);
    return { kid, signature: await this.provider.sign(kid, payload) };
  }
}
