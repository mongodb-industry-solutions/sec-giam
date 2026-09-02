import { Db } from 'mongodb';
import { CaepEvent, SignalsService } from './signals.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { RealmService } from '../../realm/services/realm.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';

/**
 * The one place a CAEP signal is emitted from.
 *
 * Every emitter needs the same five steps in the same order: resolve the realm for its issuer, ask
 * who subscribed, mint, deliver, record what happened. Written once because the interesting parts
 * are the parts that are easy to get wrong individually, and getting them wrong is silent: an
 * emitter that forgets to record delivers signals nobody can prove arrived, and one that forgets to
 * swallow turns a third party being unreachable into the revocation itself failing.
 */
export interface DispatchInput {
  realmId: string;
  tenantId: string;
  event: CaepEvent;
  subjectId: string;
  /** Only for session scoped events. Absent means the signal is about the subject as a whole. */
  sessionId?: string;
  reason: string;
  /** What the audit line is filed under, and what the signal was about. */
  category: string;
  target: { type: string; ref: string };
}

export class SignalDispatcher {
  constructor(private readonly db: Db) {}

  /**
   * Emits one signal to every subscribed receiver, and records that it tried.
   *
   * The RECORD is the part that matters when something goes wrong: a delivery nobody can prove
   * happened is indistinguishable from one that never did, and after an incident the question is
   * whether the receiver was told rather than whether we meant to tell it.
   *
   * The elapsed time is recorded per signal, because propagation latency is the number this whole
   * layer is judged on and an unmeasured objective is an aspiration.
   */
  async dispatch(input: DispatchInput): Promise<void> {
    try {
      const realm = await new RealmService(this.db).byId(input.realmId);
      if (!realm) return;

      const ring = new KeyRing(new MongoSigningKeyStore(this.db));
      const signals = new SignalsService(this.db, ring);
      const receivers = await signals.subscribers(input.realmId, input.event);
      if (receivers.length === 0) return;

      const startedAt = Date.now();
      const signal = await signals.mint({
        realmId: input.realmId,
        tenantId: input.tenantId,
        event: input.event,
        subjectId: input.subjectId,
        ...(input.sessionId ? { sessionId: input.sessionId } : {}),
        reason: input.reason,
      }, realm.issuer);
      const outcomes = await signals.deliver(signal, receivers);

      void new SecurityEventService(this.db).record({
        realmId: input.realmId,
        tenantId: input.tenantId,
        category: input.category,
        action: `signal.${input.event.replace(/-/g, '_')}.delivered`,
        outcome: outcomes.every((outcome) => outcome.delivered) ? 'success' : 'failure',
        subjectId: input.subjectId,
        target: input.target,
        detail: {
          // The number this layer is judged on.
          propagationMs: Date.now() - startedAt,
          receivers: outcomes.length,
          delivered: outcomes.filter((outcome) => outcome.delivered).length,
          outcomes,
          fallback: 'a receiver that was not reached can still poll the signed feed',
        },
      });
    } catch {
      /**
       * Swallowed on purpose, and this is the one place that deserves saying twice.
       *
       * Signalling is best effort by design. The state change has already happened, the event is
       * already in the audit trail, and the feed will serve it to any receiver that asks. Letting a
       * signalling failure escape would turn "we could not tell a third party" into "the operation
       * failed", which is worse for the caller and no better for the receiver.
       */
    }
  }
}
