import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { SecurityEventService } from '../services/securityEvent.service';
import { FlowAuditService } from '../services/flowAudit.service';
import { TrailDigestService } from '../services/trailDigest.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
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
 *
 * A person's own slice is their own events plus the ones that named them as a stakeholder when they
 * were recorded. That list is written at the time by the code that knows who held the standing; it is
 * never a match on the target reference, which would let any caller read events about any record whose
 * identifier they could guess.
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
          txn: {
            type: 'string',
            description:
              'The flow, which is what an access token carries as its `txn` claim. The name an '
              + 'auditor reads off a token, so it is the primary one here.',
          },
          correlationId: { type: 'string', description: 'The same field under its internal name. Kept so nothing breaks.' },
          scope: {
            type: 'string',
            enum: ['own', 'stakeholder', 'subject'],
            description:
              'Whose events. `own` is what the caller caused, `stakeholder` is what they are entitled '
              + 'to see without having caused it, `subject` needs an oversight role. The console '
              + 'applied this in the BROWSER, which is a presentation choice rather than an access '
              + 'control and fails open the moment somebody calls the API directly.',
          },
          actor: {
            type: 'string',
            enum: ['person', 'application'],
            description: 'Whether a person drove it or an application acted for them. Also browser-side until now.',
          },
          from: { type: 'string', format: 'date-time' },
          to: { type: 'string', format: 'date-time' },
          offset: {
            type: 'integer',
            default: 0,
            description:
              'Paging past the first batch, which was impossible before. BOUND IT WITH `to` if you '
              + 'need stable pages: the trail is written to continuously, so on an unbounded query '
              + 'new events land at the top between requests and shift a page boundary under you. '
              + 'That is a property of offset paging rather than a defect, and the fix is to page a '
              + 'closed window.',
          },
          limit: { type: 'integer', default: 100 },
          format: {
            type: 'string',
            enum: ['json', 'csv'],
            description:
              'An evidence export, produced HERE from the query rather than in a browser from a '
              + 'display page. The old export was bounded by whatever the screen had fetched, and no '
              + 'other caller could obtain one.',
          },
        },
      },
      response: {
        200: {
          description: 'The matching events, newest first.',
          type: 'object',
          additionalProperties: false,
          required: ['events'],
          properties: {
            // The console paged over one fetched batch because there was no total to page against,
            // so "page 5" showed whatever the limit had returned and nothing beyond it.
            total: { type: 'integer', description: 'How many match the query, not how many were returned.' },
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
                  principalSubjectId: {
                    type: 'string',
                    description: 'Present when an application acted FOR this principal rather than the principal acting themselves.',
                  },
                  agentId: { type: 'string', description: 'The application that acted, when one did.' },
                  stakeholder: {
                    type: 'boolean',
                    description:
                      'Present when the reader did not cause this event but is entitled to see it, '
                      + 'because it changed something they hold: who administers an application they '
                      + 'own, an authorisation of theirs, or authority granted over them.',
                  },
                  target: {
                    type: 'object',
                    additionalProperties: true,
                    properties: { type: { type: 'string' }, ref: { type: 'string' } },
                  },
                  detail: {
                    type: 'object',
                    additionalProperties: true,
                    description: 'What the event was about: the grant type, the application\'s name, the scopes. Credential material is removed before it is written.',
                  },
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
      outcome?: 'success' | 'failure'; correlationId?: string; txn?: string;
      scope?: 'own' | 'stakeholder' | 'subject'; actor?: 'person' | 'application';
      from?: string; to?: string; limit?: number; offset?: number; format?: 'json' | 'csv';
    };

    const realm = await new RealmService(fastify.db).byName((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    // Reading the realm's trail is a permission, and so is reading somebody else's slice of it. A
    // caller holding neither is narrowed to their own events rather than refused, because a person
    // is always entitled to their own.
    const wantsOthers = !query.subjectId || query.subjectId !== caller.subjectId;
    let subjectId: string | undefined = caller.subjectId;
    // Set when the narrowing is the self-scoped one, which also admits the events that name the
    // caller as a stakeholder. An oversight read is not widened this way: it already sees everything.
    let selfScoped = true;
    if (wantsOthers) {
      const decision = await new DecisionService(fastify.db)
        .check(realm.realmId, caller.subjectId, caller.clientId, 'auditEvents', 'view');
      if (decision.effect === 'allow') {
        subjectId = query.subjectId;
        selfScoped = false;
      } else if (query.subjectId) {
        return reply.status(403).send(problem(403, 'Not permitted', decision.reason));
      }
    }

    /**
     * ONE filter, and the server applies all of it.
     *
     * `scope` and `actor` were applied in the browser, which the header comment of this file calls
     * out as a defect in the abstract: a filter applied by a client after the fact is a presentation
     * choice rather than an access control, and it fails open the moment somebody calls the API
     * directly. They are parameters now, and the console consumes them instead of reimplementing.
     */
    const filter = {
      realmId: realm.realmId,
      ...(selfScoped ? { subjectIdOrStakeholder: caller.subjectId } : subjectId ? { subjectId } : {}),
      // Entitled to see it without having caused it. Only meaningful for a self-scoped read: an
      // oversight caller already sees everything, so narrowing them to it would be a different query.
      ...(selfScoped && query.scope === 'stakeholder' ? { stakeholderOnly: caller.subjectId } : {}),
      ...(query.clientId ? { clientId: query.clientId } : {}),
      ...(query.action ? { action: query.action } : {}),
      ...(query.outcome ? { outcome: query.outcome } : {}),
      ...(query.actor ? { actor: query.actor } : {}),
      // `txn` is the name an auditor reads off a token; `correlationId` is the same field's internal
      // name, kept so nothing that already uses it breaks.
      ...(query.txn ?? query.correlationId ? { correlationId: (query.txn ?? query.correlationId) as string } : {}),
      ...(query.from ? { from: new Date(query.from) } : {}),
      ...(query.to ? { to: new Date(query.to) } : {}),
      ...(query.offset ? { offset: query.offset } : {}),
      ...(query.limit ? { limit: query.limit } : {}),
    };

    const service = new SecurityEventService(fastify.db);
    const [events, total] = await Promise.all([service.query(filter), service.count(filter)]);

    /**
     * The evidence export, produced HERE from the query.
     *
     * It was assembled in the browser from whatever the screen had fetched, so an export was bounded
     * by a display limit rather than by what was asked for, and no other caller could obtain one at
     * all. The filter travels in the file, which the previous implementation got right and which is
     * kept: a file that does not say what it is a slice of is misleading evidence.
     */
    if (query.format === 'csv') {
      const columns = ['ts', 'action', 'outcome', 'cause', 'subjectId', 'clientId', 'correlationId'];
      const escape = (value: unknown) => `"${String(value ?? '').replace(/"/g, '""')}"`;
      const rows = events.map((event) => [
        event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
        event.action, event.outcome, event.cause ?? '',
        event.meta?.subjectId ?? '', event.meta?.clientId ?? '', event.correlationId ?? '',
      ].map(escape).join(','));
      reply.header('content-type', 'text/csv; charset=utf-8');
      reply.header('content-disposition', 'attachment; filename="security-events.csv"');
      // CRLF, which is what RFC 4180 specifies for CSV and what a spreadsheet expects.
      const lines = [`# filter: ${JSON.stringify(query)}`, columns.join(','), ...rows];
      return reply.send(lines.join('\r\n'));
    }

    return reply.send({
      total,
      events: events.map((event) => ({
        ts: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
        action: event.action,
        outcome: event.outcome,
        category: event.meta.category,
        ...(event.cause ? { cause: event.cause } : {}),
        ...(event.meta.subjectId ? { subjectId: event.meta.subjectId } : {}),
        ...(event.meta.clientId ? { clientId: event.meta.clientId } : {}),
        ...(event.correlationId ? { correlationId: event.correlationId } : {}),
        // Carried out so a reader can tell "I did this" from "an application did this for me".
        ...(event.principalSubjectId ? { principalSubjectId: event.principalSubjectId } : {}),
        ...(event.agentId ? { agentId: event.agentId } : {}),
        ...(event.target ? { target: event.target } : {}),
        ...(event.detail ? { detail: event.detail } : {}),
        // Why the reader is seeing an event they did not cause. Computed against the caller rather
        // than returning the list, because who else may see it is nobody else's business.
        ...((event.stakeholderSubjectIds ?? []).includes(caller.subjectId)
          && event.meta.subjectId !== caller.subjectId
          ? { stakeholder: true }
          : {}),
      })),
    });
  });

  /**
   * One flow, assembled, from the `txn` an auditor read off a token.
   *
   * The whole point of P10. Reconstructing this took five separate reads with five permission checks
   * and a caller stitching evidence together, which is not something a regulator obtains with an
   * HTTP client. It is ONE aggregation now.
   */
  fastify.get('/realms/:realm/audit/flows/:txn', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'auditFlow',
      tags: ['audit'],
      summary: 'Everything that happened in one authorization flow',
      description:
        'No applicable standard for the shape; the obligation is that identity evidence be readable '
        + 'after the fact. Assembled from the `txn` claim an access token carries: the events in '
        + 'order, the tokens the flow minted, the records that still exist, and the records that do '
        + 'not WITH THE REASON. The ticket is TTL bounded in minutes by design, so an audit after '
        + 'the fact always finds it gone, and saying so is different from omitting it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'txn'],
        properties: { realm: { type: 'string' }, txn: { type: 'string' } },
      },
      response: {
        200: {
          description: 'The flow.',
          type: 'object',
          additionalProperties: true,
          required: ['txn', 'events', 'tokens', 'gone'],
          properties: {
            txn: { type: 'string' },
            subjectId: { type: 'string' },
            clientId: { type: 'string' },
            events: { type: 'array', items: { type: 'object', additionalProperties: true } },
            tokens: {
              type: 'array',
              description: 'Read from the trail, because nothing redeemable is kept at rest.',
              items: { type: 'object', additionalProperties: true },
            },
            session: { type: 'object', additionalProperties: true },
            grant: { type: 'object', additionalProperties: true },
            principal: { type: 'object', additionalProperties: true },
            gone: {
              type: 'array',
              description: 'What no longer exists, and why. Absence with a reason is evidence.',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['what', 'because'],
                properties: { what: { type: 'string' }, because: { type: 'string' } },
              },
            },
          },
          examples: [{
            txn: 'f7c1a9e0-3b52-4d18-9a44-0e6b2c8d5511',
            events: [{ ts: '2026-09-04T10:00:00.000Z', action: 'authorization.code_issued', outcome: 'success' }],
            tokens: [{ jti: '0f2c1a44', at: '2026-09-04T10:00:01.000Z', action: 'token.issued' }],
            gone: [{ what: 'authorization request', because: 'the ticket is TTL bounded in minutes by design' }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such flow, or not one this caller may read.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, txn } = request.params as { realm: string; txn: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const flow = await new FlowAuditService(fastify.db).byTxn(realm.realmId, txn);

    /**
     * A `txn` is readable by anybody holding the token, so this must not become a master key.
     *
     * The caller sees it if they are its subject, or if they hold the oversight permission. Anything
     * else is 404 AND NOT 403: a 403 would confirm that the flow exists, which is exactly what
     * somebody holding a captured identifier is trying to find out.
     */
    const mine = flow?.subjectId === caller.subjectId;
    if (!mine) {
      const decision = await new DecisionService(fastify.db)
        .check(realm.realmId, caller.subjectId, caller.clientId, 'auditEvents', 'view');
      if (decision.effect !== 'allow') return reply.status(404).send(problem(404, 'No such flow'));
    }
    if (!flow) return reply.status(404).send(problem(404, 'No such flow'));

    return reply.send(flow);
  });

  /**
   * The flow one token belongs to, when somebody holds a token and nothing else.
   *
   * Answers with the correlator rather than with the flow, so reading the flow goes through the
   * permission-checked route above. A second way in would be a second place to get the check wrong.
   */
  fastify.get('/realms/:realm/audit/tokens/:jti', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'auditToken',
      tags: ['audit'],
      summary: 'Which flow a token belongs to',
      description:
        'No applicable standard. Resolves the `jti` of an access token to the `txn` of the flow that '
        + 'minted it, which is the entry point when an investigation starts from one token. It '
        + 'answers with the correlator and not with the flow, so reading the flow still goes through '
        + 'the permission check on the flow route.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'jti'],
        properties: { realm: { type: 'string' }, jti: { type: 'string' } },
      },
      response: {
        200: {
          description: 'The flow this token was minted in.',
          type: 'object',
          additionalProperties: false,
          required: ['txn', 'at'],
          properties: { txn: { type: 'string' }, at: { type: 'string' } },
          examples: [{ txn: 'f7c1a9e0-3b52-4d18-9a44-0e6b2c8d5511', at: '2026-09-04T10:00:01.000Z' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No issuance recorded for that token.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, jti } = request.params as { realm: string; jti: string };
    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const found = await new FlowAuditService(fastify.db).txnForJti(realm.realmId, jti);
    if (!found) return reply.status(404).send(problem(404, 'No issuance recorded for that token'));
    return reply.send(found);
  });

  /**
   * Seals a window of the trail, so alteration afterwards is detectable.
   *
   * See `TrailDigestService` for why this is a digest per window rather than a hash chain per
   * record: a chain cannot be made atomic on a time series collection and would have gaps, and a
   * gap is indistinguishable from tampering.
   *
   * Reading it requires the oversight permission. The digest itself discloses nothing about the
   * events, but the COUNT does, and how many security events a realm recorded in an hour is not
   * public.
   */
  fastify.post('/realms/:realm/audit/digest', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'sealAuditWindow',
      tags: ['audit'],
      summary: 'Seal a window of the trail, or verify a seal',
      description:
        'No applicable standard for the shape; the obligation is PCI DSS 10.3.2 to 10.3.4, that '
        + 'evidence be protected from alteration and that alteration be detectable. Computes a '
        + 'signed digest over a closed window. Export it: a digest held on the same cluster as the '
        + 'events it protects proves nothing. Send `digest` and `events` back to verify a window '
        + 'against what it was when sealed.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['from', 'to'],
        additionalProperties: false,
        properties: {
          from: { type: 'string', format: 'date-time' },
          to: { type: 'string', format: 'date-time', description: 'Exclusive. Seal only CLOSED windows: a window still being written to will not match later.' },
          digest: { type: 'string', description: 'Present to VERIFY rather than to seal.' },
          events: { type: 'integer', description: 'The count as it was when sealed. Required alongside `digest`.' },
        },
      },
      response: {
        200: {
          description: 'The seal, or the verdict when verifying.',
          type: 'object',
          additionalProperties: true,
          properties: {
            from: { type: 'string' },
            to: { type: 'string' },
            events: { type: 'integer' },
            digest: { type: 'string' },
            jwt: { type: 'string', description: 'The same, signed by the realm key. Verified through the published key set.' },
            intact: { type: 'boolean', description: 'Present when verifying. False means the window is not what it was.' },
            eventsThen: { type: 'integer' },
            eventsNow: { type: 'integer' },
          },
          examples: [{ from: '2026-09-04T00:00:00.000Z', to: '2026-09-05T00:00:00.000Z', events: 412, digest: 'a3f1...' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits reading the trail of this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as { from: string; to: string; digest?: string; events?: number };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const decision = await new DecisionService(fastify.db)
      .check(realm.realmId, caller.subjectId, caller.clientId, 'auditEvents', 'view');
    if (decision.effect !== 'allow') {
      return reply.status(403).send(problem(403, 'Not permitted', decision.reason));
    }

    const service = new TrailDigestService(fastify.db, new KeyRing(new MongoSigningKeyStore(fastify.db)));

    if (body.digest !== undefined) {
      const verdict = await service.verify(realm.realmId, {
        from: body.from, to: body.to, digest: body.digest, events: body.events ?? -1,
      });
      return reply.send({ from: body.from, to: body.to, ...verdict });
    }

    return reply.send(await service.seal(
      realm.realmId, new Date(body.from), new Date(body.to), realm.issuer,
    ));
  });
}
