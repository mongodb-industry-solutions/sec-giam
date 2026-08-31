import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { SecurityEventService } from '../services/securityEvent.service';
import { DecisionService } from '../../authorization/services/decision.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

/**
 * The identity trail, queryable.
 *
 * Who may read which events is decided here and nowhere else. A person sees their own; a caller
 * whose role grants it sees the realm. A consuming application forwards the caller's token and
 * renders what comes back, and must not filter the result: a filter applied by a client after the
 * fact is a presentation choice, not an access control, and it fails open the moment somebody calls
 * the API directly.
 */
export async function securityEventController(fastify: FastifyInstance) {
  fastify.get('/realms/:realm/security-events', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'querySecurityEvents',
      tags: ['audit'],
      summary: 'The identity and access trail',
      description:
        'No applicable standard for the query shape; the record follows the guidance that an audit '
        + 'entry must say who did what, to what, when and with what outcome. Only identity evidence '
        + 'is here: a consuming application\'s business events stay with that application, because '
        + 'two sources of truth for one event is worse than one imperfect source.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      querystring: {
        type: 'object',
        properties: {
          subjectId: { type: 'string', description: 'Defaults to the caller. Another principal requires an oversight role.' },
          clientId: { type: 'string' },
          action: { type: 'string' },
          outcome: { type: 'string', enum: ['success', 'failure'] },
          correlationId: { type: 'string', description: 'Groups every step of one flow.' },
          from: { type: 'string', format: 'date-time' },
          to: { type: 'string', format: 'date-time' },
          limit: { type: 'integer', default: 100 },
        },
      },
      response: {
        200: {
          description: 'The matching events, newest first.',
          type: 'object',
          additionalProperties: false,
          required: ['events'],
          properties: {
            events: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  ts: { type: 'string' },
                  action: { type: 'string' },
                  outcome: { type: 'string' },
                  category: { type: 'string' },
                  cause: { type: 'string' },
                  subjectId: { type: 'string' },
                  clientId: { type: 'string' },
                  correlationId: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            events: [{
              ts: '2026-08-28T14:02:55.000Z',
              action: 'authentication.password',
              outcome: 'failure',
              category: 'authentication',
              cause: 'bad_credential',
              subjectId: 'sub-4821',
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants sight of another principal.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const query = request.query as {
      subjectId?: string; clientId?: string; action?: string;
      outcome?: 'success' | 'failure'; correlationId?: string;
      from?: string; to?: string; limit?: number;
    };

    const realm = await new RealmService(fastify.db).byName((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    // Reading the realm's trail is a permission, and so is reading somebody else's slice of it. A
    // caller holding neither is narrowed to their own events rather than refused, because a person
    // is always entitled to their own.
    const wantsOthers = !query.subjectId || query.subjectId !== caller.subjectId;
    let subjectId: string | undefined = caller.subjectId;
    if (wantsOthers) {
      const decision = await new DecisionService(fastify.db)
        .check(realm.realmId, caller.subjectId, caller.clientId, 'auditEvents', 'view');
      if (decision.effect === 'allow') {
        subjectId = query.subjectId;
      } else if (query.subjectId) {
        return reply.status(403).send(problem(403, 'Not permitted', decision.reason));
      }
    }

    const events = await new SecurityEventService(fastify.db).query({
      realmId: realm.realmId,
      ...(subjectId ? { subjectId } : {}),
      ...(query.clientId ? { clientId: query.clientId } : {}),
      ...(query.action ? { action: query.action } : {}),
      ...(query.outcome ? { outcome: query.outcome } : {}),
      ...(query.correlationId ? { correlationId: query.correlationId } : {}),
      ...(query.from ? { from: new Date(query.from) } : {}),
      ...(query.to ? { to: new Date(query.to) } : {}),
      ...(query.limit ? { limit: query.limit } : {}),
    });

    return reply.send({
      events: events.map((event) => ({
        ts: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
        action: event.action,
        outcome: event.outcome,
        category: event.meta.category,
        ...(event.cause ? { cause: event.cause } : {}),
        ...(event.meta.subjectId ? { subjectId: event.meta.subjectId } : {}),
        ...(event.meta.clientId ? { clientId: event.meta.clientId } : {}),
        ...(event.correlationId ? { correlationId: event.correlationId } : {}),
      })),
    });
  });
}
