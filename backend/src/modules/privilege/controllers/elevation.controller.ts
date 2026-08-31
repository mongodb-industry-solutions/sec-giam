import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ElevationService, isElevationRefusal } from '../services/elevation.service';
import { DecisionService } from '../../authorization/services/decision.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

/**
 * Asking for temporary authority, approving it, and taking it back.
 *
 * The authority holds the record and makes the decision; the consuming application shows a button.
 * That split is the reason this exists here at all: when the capability lived in an application, the
 * application was also the only place that knew who held it, and nobody could ask across the
 * platform.
 */
export async function elevationController(fastify: FastifyInstance) {
  const base = '/realms/:realm/elevations';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const elevationView = {
    type: 'object',
    additionalProperties: true,
    required: ['assignmentId', 'subjectId', 'roleId'],
    properties: {
      assignmentId: { type: 'string' },
      subjectId: { type: 'string' },
      roleId: { type: 'string' },
      scope: { type: 'object', additionalProperties: true },
      justification: { type: 'string' },
      grantedBy: { type: 'string' },
      approvalRef: { type: 'string' },
      grantedAt: { type: 'string' },
      notBefore: { type: 'string', description: 'Present while awaiting approval, so the assignment grants nothing yet.' },
      expiresAt: { type: 'string' },
      ephemeral: { type: 'boolean' },
    },
    examples: [{
      assignmentId: 'elev-4c1f',
      subjectId: 'sub-4821',
      roleId: 'role-investigator-sensitive',
      scope: { kind: 'case', ref: 'case-2291' },
      justification: 'Reviewing a disputed transaction reported by the account holder.',
      grantedBy: 'sub-4821',
      approvalRef: 'sub-1180',
      expiresAt: '2026-08-29T18:00:00.000Z',
      ephemeral: true,
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'requestElevation',
      tags: ['privilege'],
      summary: 'Ask for temporary authority',
      description:
        'No applicable standard; this is privileged access management, where the practice is '
        + 'time-bound, justified and reviewable access rather than a standing permission. The reason '
        + 'is required, because an elevation with no stated reason cannot be reviewed afterwards and '
        + 'the moment of asking is the only time anybody actually knows it.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['roleName', 'justification'],
        additionalProperties: false,
        properties: {
          scopeKind: { type: 'string', description: 'What kind of thing this is bound to, in the caller\'s vocabulary.' },
          scopeRef: { type: 'string', description: 'Which one. This authority never learns what it names.' },
          justification: { type: 'string', minLength: 1 },
          permissions: {
            type: 'array',
            items: {
              type: 'object',
              required: ['resource', 'action'],
              properties: { resource: { type: 'string' }, action: { type: 'string' } },
            },
          },
          roles: { type: 'array', items: { type: 'string' } },
          durationSeconds: { type: 'integer' },
        },
      },
      response: {
        200: { ...elevationView, description: 'The elevation, pending or already in force.' },
        400: { $ref: 'Problem#', description: 'No justification was given.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const body = request.body as {
      roleName: string; justification: string;
      scope?: { kind: string; ref: string }; durationSeconds?: number;
    };

    // Whether a reviewer is needed is the realm's policy. A realm that reviews elevations and one
    // that does not are the same build with different configuration.
    const requiresApproval = (realm as { requiresElevationApproval?: boolean }).requiresElevationApproval ?? true;

    const outcome = await new ElevationService(fastify.db).request(realm, {
      // Always the caller's own. Elevating somebody else is a different act with a different route,
      // not a field on this one.
      subjectId: caller.subjectId,
      requestedBy: caller.subjectId,
      requiresApproval,
      ...body,
    });
    if (isElevationRefusal(outcome)) return reply.status(outcome.status as 400).send(problem(outcome.status, outcome.title, outcome.detail));
    return reply.send(outcome);
  });

  fastify.post(`${base}/:assignmentId/approve`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'approveElevation',
      tags: ['privilege'],
      summary: 'Approve somebody else\'s request',
      description:
        'No applicable standard; privileged access management practice. The approver can never be the '
        + 'requester: approving your own request is not a review, it is the permission granted '
        + 'permanently with extra steps. The clock starts at approval, so time spent waiting for a '
        + 'reviewer is not deducted from the time the work gets.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'assignmentId'],
        properties: { realm: { type: 'string' }, assignmentId: { type: 'string' } },
      },
      response: {
        200: { ...elevationView, description: 'The elevation, now in force.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'Self-approval, or no role permitting approval.' },
        404: { $ref: 'Problem#', description: 'No such elevation.' },
        409: { $ref: 'Problem#', description: 'That elevation is not awaiting approval.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, assignmentId } = request.params as { realm: string; assignmentId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const decision = await new DecisionService(fastify.db)
      .check(realm.realmId, caller.subjectId, caller.clientId, 'elevations', 'approve');
    if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));

    const outcome = await new ElevationService(fastify.db).approve(realm, assignmentId, caller.subjectId);
    if (isElevationRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));
    return reply.send(outcome);
  });

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listElevationsInForce',
      tags: ['privilege'],
      summary: 'Who holds elevated access right now',
      description:
        'No applicable standard; privileged access management practice. This is the question the '
        + 'signed-capability design it replaces could not answer at all, and an ordinary one to ask '
        + 'during an incident.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          state: {
            type: 'string',
            enum: ['in-force', 'pending'],
            default: 'in-force',
            description: 'Pending requests are listed too, because a queue nobody can see is a request that expires unnoticed.',
          },
        },
      },
      response: {
        200: {
          description: 'Every elevation in the requested state.',
          type: 'object',
          additionalProperties: false,
          required: ['elevations'],
          properties: { elevations: { type: 'array', items: elevationView } },
          examples: [{ elevations: [elevationView.examples[0]] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits this.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const decision = await new DecisionService(fastify.db)
      .check(realm.realmId, caller.subjectId, caller.clientId, 'elevations', 'view');
    if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));

    const { state } = request.query as { state?: 'in-force' | 'pending' };
    const service = new ElevationService(fastify.db);
    return reply.send({
      elevations: state === 'pending'
        ? await service.listPending(realm.realmId)
        : await service.listInForce(realm.realmId),
    });
  });

  fastify.delete(`${base}/:assignmentId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'revokeElevation',
      tags: ['privilege'],
      summary: 'End an elevation before it expires',
      description:
        'No applicable standard; privileged access management practice. The other thing the design '
        + 'this replaces could not do: a capability granted in error used to run to its expiry no '
        + 'matter what anyone decided afterwards. The holder may always end their own.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'assignmentId'],
        properties: { realm: { type: 'string' }, assignmentId: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: { reason: { type: 'string' } },
      },
      response: {
        200: {
          description: 'Ended.',
          type: 'object',
          additionalProperties: false,
          required: ['revoked'],
          properties: { revoked: { type: 'boolean' }, assignmentId: { type: 'string' } },
          examples: [{ revoked: true, assignmentId: 'elev-4c1f' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits ending another principal\'s.' },
        404: { $ref: 'Problem#', description: 'No such elevation in a state that can be ended.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, assignmentId } = request.params as { realm: string; assignmentId: string };
    const { reason } = (request.body ?? {}) as { reason?: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const service = new ElevationService(fastify.db);
    const held = await service.listInForce(realm.realmId);
    const target = held.find((elevation) => elevation.assignmentId === assignmentId);

    // Giving up your own authority never needs a permission. Taking away somebody else's does.
    if (target && target.subjectId !== caller.subjectId) {
      const decision = await new DecisionService(fastify.db)
        .check(realm.realmId, caller.subjectId, caller.clientId, 'elevations', 'manage');
      if (decision.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', decision.reason));
    }

    const revoked = await service.revoke(realm, assignmentId, caller.subjectId, reason ?? 'no reason given');
    if (!revoked) return reply.status(404).send(problem(404, 'No such elevation'));
    return reply.send({ revoked: true, assignmentId });
  });
}
