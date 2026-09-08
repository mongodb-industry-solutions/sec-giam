import { Db } from 'mongodb';
import { randomUUID } from 'crypto';
import { RESOURCE_COLLECTION } from '../../../shared/models/collections';
import { ResourceRecord } from '../models/resource.model';
import { KeyRing } from '../../keys/services/keyRing.service';
import { JwtTokenFormat } from '../../oauth/services/jwtTokenFormat';

/**
 * Telling a resource server that something changed, before its token expires.
 *
 * The problem this solves: nothing about centralised revocation reaches a resource server that
 * verifies tokens on its own, which is exactly what makes local verification cheap. Deleting a
 * session revokes access here and the holder's existing access token keeps working there until it
 * expires.
 *
 * Three layers, weakest guarantee first, and each is worth having on its own:
 *
 * 1. SHORT TOKEN LIFETIME. Five minutes, so the worst case propagation is five minutes with no
 *    infrastructure at all. This is the floor and it is always in force.
 * 2. CHANGE STREAMS, for validators inside this process. Milliseconds, no polling. Implemented in
 *    `sessionWatch.ts`.
 * 3. SSF and CAEP, for resource servers outside it. This file.
 *
 * OpenID Shared Signals Framework defines the transmitter and the stream; CAEP defines the event
 * types. A receiver that cannot implement SSF polls the signed feed instead, which returns the same
 * events, so a consumer is never forced to adopt a framework to learn about a revocation.
 *
 * Stream configuration needs no collection: it is a bounded sub document on the receiving resource.
 */

/** The CAEP event types this authority emits. Not an open set: each one has a defined meaning. */
export type CaepEvent =
  | 'session-revoked'
  | 'credential-change'
  | 'assurance-level-change'
  | 'token-claims-change';

const CAEP_URI: Record<CaepEvent, string> = {
  'session-revoked': 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  'credential-change': 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
  'assurance-level-change': 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
  'token-claims-change': 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
};

export interface SignalInput {
  realmId: string;
  tenantId: string;
  event: CaepEvent;
  /** Who the signal is about. A receiver matches this against its own sessions. */
  subjectId: string;
  /** The session, where the event concerns one. */
  sessionId?: string;
  /** Why, in terms a receiver can act on rather than a sentence for a human. */
  reason?: string;
  occurredAt?: Date;
}

/** A Security Event Token, as it is stored for the feed and sent to a receiver. */
export interface SecurityEventToken {
  signalId: string;
  realmId: string;
  event: CaepEvent;
  subjectId: string;
  sessionId?: string;
  reason?: string;
  issuedAt: string;
  /** The signed SET. A receiver verifies this against the realm's published key set. */
  jwt: string;
}

/**
 * Builds and delivers the signals for one change.
 *
 * Delivery failures never propagate to the caller. Revoking a session must succeed whether or not a
 * receiver is reachable: a revocation that could be blocked by an unreachable third party would be
 * a revocation an attacker could prevent by making that party unreachable.
 */
export class SignalsService {
  constructor(private readonly db: Db, private readonly ring: KeyRing) {}

  private get resources() {
    return this.db.collection<ResourceRecord>(RESOURCE_COLLECTION);
  }

  /** Every resource in the realm that asked to hear about this event type. */
  async subscribers(realmId: string, event: CaepEvent): Promise<ResourceRecord[]> {
    return this.resources
      .find(
        {
          realmId,
          'signalStream.events': event,
          status: 'active',
        },
        { projection: { _id: 0 } },
      )
      .toArray();
  }

  /**
   * The signed Security Event Token for one signal.
   *
   * Signed with the realm's own signing key, so a receiver verifies it exactly as it verifies an
   * access token: the same JWKS, the same key rotation, nothing new to configure. An unsigned
   * signal would be an instruction to end somebody's session that anybody could forge.
   */
  async mint(input: SignalInput, issuer: string): Promise<SecurityEventToken> {
    const occurredAt = input.occurredAt ?? new Date();
    const seconds = Math.floor(occurredAt.getTime() / 1000);
    const signalId = randomUUID();

    const format = new JwtTokenFormat(this.ring, input.realmId, 'secevent+jwt');
    const kid = await this.ring.signingKid(input.realmId);
    const jwt = await format.issue({
      iss: issuer,
      jti: signalId,
      iat: seconds,
      // RFC 8935: the audience is the receiver's stream. Left to the delivery step, which knows it.
      events: {
        [CAEP_URI[input.event]]: {
          subject: { format: 'opaque', id: input.subjectId },
          event_timestamp: seconds,
          ...(input.reason ? { reason_admin: { en: input.reason } } : {}),
          ...(input.sessionId ? { session: { format: 'opaque', id: input.sessionId } } : {}),
        },
      },
    }, kid);

    return {
      signalId,
      realmId: input.realmId,
      event: input.event,
      subjectId: input.subjectId,
      ...(input.sessionId ? { sessionId: input.sessionId } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      issuedAt: occurredAt.toISOString(),
      jwt,
    };
  }

  /**
   * Delivers one signal to every subscribed receiver, and never throws.
   *
   * Push receivers are posted to. Poll receivers are not contacted at all: they read the feed, and
   * posting to them would be delivering a signal to somebody who did not ask to be interrupted.
   *
   * Returns what happened per receiver, so the caller can record it. A silent delivery is a
   * delivery nobody can prove happened.
   */
  async deliver(
    signal: SecurityEventToken,
    receivers: ResourceRecord[],
  ): Promise<Array<{ resourceId: string; delivered: boolean; status?: number; error?: string }>> {
    const outcomes: Array<{ resourceId: string; delivered: boolean; status?: number; error?: string }> = [];

    for (const receiver of receivers) {
      const stream = receiver.signalStream;
      if (!stream || stream.deliveryMethod !== 'push' || !stream.endpoint) continue;
      try {
        const response = await fetch(stream.endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/secevent+jwt' },
          body: signal.jwt,
          // A receiver that hangs must not hold a revocation open. The signal is already durable in
          // the feed, so giving up here loses nothing: the receiver can still poll for it.
          signal: AbortSignal.timeout(5_000),
        });
        outcomes.push({ resourceId: receiver.resourceId, delivered: response.ok, status: response.status });
      } catch (cause) {
        outcomes.push({
          resourceId: receiver.resourceId,
          delivered: false,
          error: cause instanceof Error ? cause.message : 'delivery failed',
        });
      }
    }

    return outcomes;
  }
}
