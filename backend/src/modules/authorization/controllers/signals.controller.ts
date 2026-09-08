import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { SignalsService, CaepEvent } from '../services/signals.service';
import { AUDIT_COLLECTION } from '../../../shared/models/collections';
import { problem } from '../../../shared/models/problem';
import { requireAuthorityCaller } from '../../../vendors/middleware/authorityAuth';

/**
 * The fallback feed, for a receiver that cannot implement Shared Signals.
 *
 * P10.3. SSF push is the primary path and this returns THE SAME EVENTS, so adopting a framework is
 * never the price of learning about a revocation. A receiver polls this, caches what it reads, and
 * carries on.
 *
 * Read from `audit` rather than from a collection of its own, and that is deliberate rather than
 * frugal: a signal IS a projection of an event that already had to be recorded as evidence. A
 * separate store would be a second copy of the same fact, free to disagree with the first, and it
 * would have made the model fourteen collections to hold data that was already there.
 *
 * Signed per entry, so a receiver verifies each event against the realm's published key set exactly
 * as it verifies an access token. An unsigned feed would be an instruction to end somebody's
 * session that anybody could forge.
 */

/** Which audit actions correspond to which CAEP event. Nothing else reaches the feed. */
const SIGNAL_ACTIONS: Record<string, CaepEvent> = {
  'authentication.session.terminated': 'session-revoked',
  'authentication.session.evicted': 'session-revoked',
  'oauth.refresh.reuse_detected': 'session-revoked',
  'credential.revoked': 'credential-change',
  'credential.registered': 'credential-change',
  'privilege.approved': 'assurance-level-change',
};

export async function signalsController(fastify: FastifyInstance) {
  const ring = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  fastify.get('/realms/:realm/signals', {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'pollSecurityEventFeed',
      tags: ['authorization'],
      summary: 'Security events since a moment, for a receiver that polls',
      description:
        'Standard-defined: OpenID Shared Signals Framework, with CAEP event types. The signed '
        + 'fallback for a receiver that cannot host an SSF push endpoint. Returns the same events '
        + 'push delivers, newest last, so a caller can replay in order and record where it stopped. '
        + 'Each entry is a Security Event Token signed by the realm, verified against the same JWKS '
        + 'as an access token.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string' } },
      },
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: {
          since: {
            type: 'string',
            description: 'ISO instant. Events at or after it. Omitted means the last hour, not everything.',
          },
          limit: { type: 'integer', minimum: 1, maximum: 500, default: 100 },
        },
      },
      response: {
        200: {
          description: 'The events, oldest first.',
          type: 'object',
          additionalProperties: false,
          required: ['signals', 'cursor'],
          properties: {
            signals: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['event', 'subjectId', 'issuedAt', 'jwt'],
                properties: {
                  event: { type: 'string' },
                  subjectId: { type: 'string' },
                  sessionId: { type: 'string' },
                  reason: { type: 'string' },
                  issuedAt: { type: 'string' },
                  jwt: { type: 'string', description: 'The signed Security Event Token.' },
                },
              },
            },
            cursor: {
              type: 'string',
              description: 'Pass as `since` next time. The instant of the last event, or the request time when empty.',
            },
          },
          examples: [{
            signals: [{
              event: 'session-revoked',
              subjectId: 'a1000070-0000-4000-8000-000000000070',
              sessionId: 'c4e2a8f1-9b3d-4c76-a5e8-2f7b1d6c9a34',
              reason: 'logout',
              issuedAt: '2026-09-02T09:41:00.000Z',
              jwt: 'eyJ0eXAiOiJzZWNldmVudCtqd3Qi…',
            }],
            cursor: '2026-09-02T09:41:00.000Z',
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const { since, limit } = request.query as { since?: string; limit?: number };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    /**
     * An omitted `since` means the LAST HOUR, not the beginning of time.
     *
     * A receiver polling for the first time should not be handed the realm's entire history, and a
     * receiver that lost its cursor should not accidentally replay a year of revocations for
     * sessions that ended long ago.
     */
    const from = since ? new Date(since) : new Date(Date.now() - 3_600_000);
    if (Number.isNaN(from.getTime())) {
      return reply.status(404).send(problem(404, 'Unreadable instant', '`since` must be an ISO instant.'));
    }

    const events = await fastify.db
      .collection<{
        ts: Date;
        action: string;
        subjectId?: string;
        cause?: string;
        target?: { type: string; ref: string };
      }>(AUDIT_COLLECTION)
      .find(
        {
          'meta.realmId': realm.realmId,
          action: { $in: Object.keys(SIGNAL_ACTIONS) },
          ts: { $gte: from },
        },
        { projection: { _id: 0 } },
      )
      .sort({ ts: 1 })
      .limit(Math.min(limit ?? 100, 500))
      .toArray();

    const signals = new SignalsService(fastify.db, ring());
    const minted = [];
    for (const event of events) {
      if (!event.subjectId) continue;
      const token = await signals.mint({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        event: SIGNAL_ACTIONS[event.action],
        subjectId: event.subjectId,
        ...(event.target?.type === 'session' ? { sessionId: event.target.ref } : {}),
        ...(event.cause ? { reason: event.cause } : {}),
        occurredAt: event.ts,
      }, realm.issuer);
      minted.push({
        event: token.event,
        subjectId: token.subjectId,
        ...(token.sessionId ? { sessionId: token.sessionId } : {}),
        ...(token.reason ? { reason: token.reason } : {}),
        issuedAt: token.issuedAt,
        jwt: token.jwt,
      });
    }

    // The cursor is the last event's instant, so a caller resumes exactly where it stopped. When
    // nothing came back it is the request time, which is what stops a poller re-reading the window.
    const cursor = minted.length > 0
      ? minted[minted.length - 1].issuedAt
      : new Date().toISOString();

    return reply.send({ signals: minted, cursor });
  });
}
