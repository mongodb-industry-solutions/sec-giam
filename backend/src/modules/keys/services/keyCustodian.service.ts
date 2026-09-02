import { Db } from 'mongodb';
import { REALM_COLLECTION } from '../../../shared/models/collections';
import { RealmRecord } from '../../realm/models/realm.model';
import { KeyRing } from './keyRing.service';
import { MongoSigningKeyStore } from './signingKeyStore';
import { registerBuiltinPorts } from '../../../shared/ports/builtins';
import { config } from '../../../config';

/**
 * The heartbeat the lease model always assumed, and nothing ran.
 *
 * `KeyRing` was written around a replica renewing its lease while it lives and a sweep retiring the
 * keys of replicas that stopped. Both were implemented, tested, and then called from nowhere. So a
 * lease was stamped once at publication and never renewed nor swept, every key stayed `active` and
 * signing-eligible forever, and each restart added another one that no operator could remove: the
 * phantom replicas lived in the database, so stopping the process could not clear them.
 *
 * Two jobs on one timer:
 *
 * RENEW this replica's own keys, which is what says "still here". A lease that nobody renews lapses,
 * and a lapsed lease is exactly the signal the sweep reads.
 *
 * RECONCILE every realm, which retires whatever has lapsed. Retiring stops signing immediately and
 * leaves the key published for the grace period, because the tokens it already signed have not
 * expired and unpublishing it sooner would reject every one of them.
 */
export class KeyCustodian {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly db: Db,
    private readonly ring: KeyRing = new KeyRing(new MongoSigningKeyStore(db)),
    private readonly log: (message: string) => void = () => {},
  ) {}

  /** One pass. Returns what it retired, so the caller can report a sweep that found something. */
  async tick(): Promise<{ renewed: number; retired: string[]; unpublished: string[] }> {
    const realms = await this.db.collection<RealmRecord>(REALM_COLLECTION)
      .find({}, { projection: { _id: 0, realmId: 1, tenantId: 1 } })
      .toArray();

    let renewed = 0;
    const retired: string[] = [];
    const unpublished: string[] = [];

    for (const realm of realms) {
      // Renew before reconciling, so this replica never sweeps its own live key on a slow pass.
      renewed += await this.ring.renewOwnLeases(realm.realmId);
      const swept = await this.ring.reconcileLeases(realm.realmId);
      retired.push(...swept.retired);
      unpublished.push(...swept.unpublished);
    }
    return { renewed, retired, unpublished };
  }

  /**
   * Starts the timer, after one immediate pass.
   *
   * The immediate pass matters on a restart: the key this instance held before is the one whose lease
   * is about to lapse, and sweeping at startup is what clears an accumulation rather than waiting a
   * heartbeat to begin clearing it.
   */
  start(): void {
    if (this.timer) return;

    const pass = async () => {
      try {
        const { retired, unpublished } = await this.tick();
        if (retired.length || unpublished.length) {
          this.log(`key custodian: retired ${retired.length}, unpublished ${unpublished.length}`);
        }
      } catch (cause) {
        // A failed sweep is not a reason to end the process: the keys stay as they were and the next
        // pass tries again. Silence would be worse than either.
        this.log(`key custodian: pass failed, ${cause instanceof Error ? cause.message : String(cause)}`);
      }
    };

    void pass();
    this.timer = setInterval(pass, Math.max(config.keys.heartbeatSeconds, 5) * 1000);
    // Nothing should be kept alive by this alone: a process whose only remaining work is a heartbeat
    // has no work.
    this.timer.unref();
  }

  stop(): void {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }
}

/** Wires the custodian for a running server. Returns null when there is no database to sweep. */
export function startKeyCustodian(db: Db | undefined, log: (message: string) => void): KeyCustodian | null {
  if (!db) return null;
  registerBuiltinPorts();
  const custodian = new KeyCustodian(db, undefined, log);
  custodian.start();
  return custodian;
}
