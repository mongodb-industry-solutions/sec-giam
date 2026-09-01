import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { PolicyAdminService, isPolicyRefusal } from '../services/policyAdmin.service';
import { PolicyDecisionService } from '../services/policyDecision.service';
import { authorityAccess, refusal } from '../services/authorityAccess';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';
import { PolicyStatement } from '../models/policy.model';

/**
 * Conditional statements, and the endpoint that shows what they actually decide.
 *
 * The statements are the easy half. The decision endpoint is the half that makes them honest: a
 * prohibition written into a document nobody can evaluate is a prohibition nobody has checked, and
 * the way a deny rule ends up wrong is that there was never a way to find out.
 *
 * Conditions are identity context only. That constraint is enforced in the request schema below and
 * again in the service, because the schema protects this surface and the service protects every
 * other way into the collection.
 */
export async function policyController(fastify: FastifyInstance) {
  const base = '/realms/:realm/policies';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const policyParams = {
    type: 'object',
    required: ['realm', 'policyId'],
    properties: { realm: { type: 'string' }, policyId: { type: 'string' } },
  } as const;

  /**
   * The whole condition vocabulary, and nothing else may be written.
   *
   * `additionalProperties: false` is the boundary that keeps this an identity authority rather than
   * a business rules engine. A free-text condition would let a policy name a monetary threshold or
   * any other business materiality, which is a judgement belonging to the system that can observe
   * the inputs. Widening this object is the only way to widen the language, so widening it is a
   * visible act in a diff.
   */
  const conditionSchema = {
    type: 'object',
    additionalProperties: false,
    description: 'Identity context only: assurance, network, time, tenant, attestation. Nothing else may be expressed.',
    properties: {
      assuranceAtLeast: { type: 'string', enum: ['aal1', 'aal2', 'aal3'], description: 'The floor the authentication must have reached.' },
      ipInRange: { type: 'array', minItems: 1, items: { type: 'string' }, description: 'Address prefixes, matched literally rather than as an expression.' },
      timeOfDayUtc: {
        type: 'object',
        additionalProperties: false,
        required: ['from', 'to'],
        description: 'UTC hours, half open. A `to` before `from` wraps midnight.',
        properties: { from: { type: 'integer', minimum: 0, maximum: 23 }, to: { type: 'integer', minimum: 0, maximum: 23 } },
      },
      tenantIs: { type: 'string', minLength: 1, description: 'The data boundary the request must be acting inside.' },
      attestationRequired: { type: 'boolean', description: 'The caller must arrive already attested.' },
    },
  } as const;

  const statementSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['effect'],
    properties: {
      effect: { type: 'string', enum: ['allow', 'deny'], description: 'Deny wins over every allow, absolutely.' },
      principals: { type: 'array', items: { type: 'string' }, description: 'Subject patterns. `*` alone, or a trailing `*` for a prefix.' },
      actions: { type: 'array', items: { type: 'string' } },
      resources: { type: 'array', items: { type: 'string' } },
      condition: conditionSchema,
      reason: { type: 'string', description: 'Carried into the decision. A decision a log cannot explain is not auditable.' },
    },
  } as const;

  const policySummary = {
    type: 'object',
    additionalProperties: false,
    required: ['policyId', 'name', 'version', 'enabled', 'statementCount', 'denyCount', 'conditionCount', 'attachedTo'],
    properties: {
      policyId: { type: 'string' },
      name: { type: 'string' },
      version: { type: 'string' },
      enabled: { type: 'boolean' },
      statementCount: { type: 'integer' },
      denyCount: { type: 'integer', description: 'How many statements prohibit. The first thing a reviewer wants to know.' },
      conditionCount: { type: 'integer' },
      attachedTo: { type: 'array', items: { type: 'string' } },
      created: { type: 'string' },
      lastModified: { type: 'string' },
    },
    examples: [{
      policyId: '2b6f0a51-d8e4-4a11-9c2e-77d4a3f1e0c2',
      name: 'administration-requires-strong-authentication',
      version: '1',
      enabled: true,
      statementCount: 1,
      denyCount: 1,
      conditionCount: 1,
      attachedTo: [],
    }],
  } as const;

  const policyDetail = {
    type: 'object',
    additionalProperties: false,
    required: [...policySummary.required, 'statements'],
    properties: { ...policySummary.properties, statements: { type: 'array', items: statementSchema } },
    examples: [{
      ...policySummary.examples[0],
      statements: [{
        effect: 'deny',
        actions: ['manage'],
        resources: ['roles'],
        condition: { assuranceAtLeast: 'aal2' },
        reason: 'Changing what a role grants requires a second factor.',
      }],
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /** Tier two, exactly as roles: the named permission AND a role that reaches past the caller's own records. */
  async function administers(realmId: string, subjectId: string, resource: string, action: string) {
    const access = await authorityAccess(fastify.db, realmId, subjectId);
    if (!access.can(resource, action) || !access.realmWide) {
      return { refused: refusal(resource, action) };
    }
    return { access };
  }

  function audit(realm: { realmId: string; tenantId: string }, action: string, subjectId: string, detail: Record<string, unknown>) {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action,
      outcome: 'success',
      subjectId,
      detail,
    });
  }

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listPolicies',
      tags: ['authorization'],
      summary: 'The conditional statements this realm applies',
      description:
        'No applicable standard. Evaluated AFTER roles and combined deny-wins, so a policy can only '
        + 'ever narrow what a role granted. Each row carries how many of its statements prohibit '
        + 'rather than permit, because a policy that denies and one that only permits are different '
        + 'objects and a single count hides which is which.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Case-insensitive match on name or version.' },
          skip: { type: 'integer', default: 0 },
          limit: { type: 'integer', default: 20, maximum: 200 },
        },
      },
      response: {
        200: {
          description: 'The policies defined in this realm.',
          type: 'object',
          additionalProperties: false,
          required: ['policies', 'total'],
          properties: { policies: { type: 'array', items: policySummary }, total: { type: 'integer' } },
          examples: [{ policies: [policySummary.examples[0]], total: 1 }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'policies', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const { q, skip, limit } = request.query as { q?: string; skip?: number; limit?: number };
    return reply.send(await new PolicyAdminService(fastify.db).list(realm.realmId, { q, skip, limit }));
  });

  fastify.get(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getPolicy',
      tags: ['authorization'],
      summary: 'One policy, statement by statement',
      description:
        'No applicable standard. Returns the statements in the order the evaluator reads them, with '
        + 'the reason each carries. The order does not change the outcome, since deny wins wherever '
        + 'it appears, but it is the order the editor and the decision trace both refer to.',
      security: [{ bearerAuth: [] }],
      params: policyParams,
      response: {
        200: { ...policyDetail, description: 'The policy.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such policy in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, policyId } = request.params as { realm: string; policyId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'policies', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const detail = await new PolicyAdminService(fastify.db).detail(realm.realmId, policyId);
    if (!detail) return reply.status(404).send(problem(404, 'No such policy'));
    return reply.send(detail);
  });

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'createPolicy',
      tags: ['authorization'],
      summary: 'State a policy',
      description:
        'No applicable standard. A condition outside the identity vocabulary is refused rather than '
        + 'stored: assurance, network, time of day, tenant and attestation are what an identity '
        + 'authority can observe, and a threshold expressing business materiality is a judgement for '
        + 'the system that can see the inputs. Test the result on the decision endpoint before '
        + 'trusting it.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['name', 'statements'],
        additionalProperties: false,
        properties: {
          name: { type: 'string', minLength: 1, pattern: '^[a-zA-Z0-9._-]+$' },
          version: { type: 'string', default: '1' },
          statements: { type: 'array', minItems: 1, items: statementSchema },
          attachedTo: { type: 'array', items: { type: 'string' } },
          enabled: { type: 'boolean', default: true },
        },
      },
      response: {
        201: { ...policyDetail, description: 'The policy as stated.' },
        400: { $ref: 'Problem#', description: 'A statement names a condition this authority cannot evaluate.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That name is taken.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'policies', 'manage');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const body = request.body as { name: string; statements: PolicyStatement[] };
    const outcome = await new PolicyAdminService(fastify.db).create(realm.realmId, realm.tenantId, body);
    if (isPolicyRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.policy.created', caller.subjectId, {
      policyId: outcome.policyId, name: outcome.name, denyCount: outcome.denyCount,
    });
    return reply.status(201).send(outcome);
  });

  fastify.patch(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'updatePolicy',
      tags: ['authorization'],
      summary: 'Change what a policy states',
      description:
        'No applicable standard. Partial: only the fields present change. The statement list is '
        + 'replaced rather than merged, because a policy is a statement of what it says and merging '
        + 'would make removing a statement impossible from here. Switching `enabled` off is the '
        + 'reversible way to stop a policy deciding, and is preferable to removing it.',
      security: [{ bearerAuth: [] }],
      params: policyParams,
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          version: { type: 'string' },
          statements: { type: 'array', minItems: 1, items: statementSchema },
          attachedTo: { type: 'array', items: { type: 'string' } },
          enabled: { type: 'boolean' },
        },
      },
      response: {
        200: { ...policyDetail, description: 'The policy, as it now stands.' },
        400: { $ref: 'Problem#', description: 'A statement names a condition this authority cannot evaluate.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such policy in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, policyId } = request.params as { realm: string; policyId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'policies', 'manage');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const outcome = await new PolicyAdminService(fastify.db).update(realm.realmId, policyId, request.body as object);
    if (outcome === null) return reply.status(404).send(problem(404, 'No such policy'));
    if (isPolicyRefusal(outcome)) return reply.status(outcome.status as 400).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.policy.updated', caller.subjectId, {
      policyId, fields: Object.keys(request.body ?? {}), enabled: outcome.enabled,
    });
    return reply.send(outcome);
  });

  fastify.delete(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'deletePolicy',
      tags: ['authorization'],
      summary: 'Remove a policy',
      description:
        'No applicable standard. Nothing else in the model references a policy, so there is no '
        + 'dependant to orphan and no refusal to make. Removing one that DENIES widens access '
        + 'immediately, which is why disabling it is offered alongside: that is reversible and this '
        + 'is not.',
      security: [{ bearerAuth: [] }],
      params: policyParams,
      response: {
        200: {
          description: 'Removed.',
          type: 'object',
          additionalProperties: false,
          required: ['removed', 'policyId'],
          properties: { removed: { type: 'boolean' }, policyId: { type: 'string' } },
          examples: [{ removed: true, policyId: '2b6f0a51-d8e4-4a11-9c2e-77d4a3f1e0c2' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such policy in this realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, policyId } = request.params as { realm: string; policyId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'policies', 'manage');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const removed = await new PolicyAdminService(fastify.db).remove(realm.realmId, policyId);
    if (!removed) return reply.status(404).send(problem(404, 'No such policy'));

    audit(realm, 'authorization.policy.removed', caller.subjectId, { policyId });
    return reply.send({ removed: true, policyId });
  });

  /**
   * The decision endpoint. Every evaluator, combined deny-wins, with the working shown.
   *
   * WHO MAY ASK is two different authorities, deliberately. Asking about YOURSELF discloses only
   * your own authority, which you already hold, so any authenticated principal may. Asking about
   * ANOTHER subject discloses that subject's authority, which is information about them rather than
   * about you, so it requires the same tier that reads the policies themselves. Treating the two as
   * one question would turn a rule tester into a way to enumerate what everybody else may do.
   *
   * The answer is not cached and does not affect the caller's own token. It says what the authority
   * would decide right now, which is the only thing a simulator can honestly claim.
   */
  fastify.post('/realms/:realm/decision', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'evaluateDecision',
      tags: ['authorization'],
      summary: 'Evaluate one authorization decision',
      description:
        'Shaped after the OpenID AuthZEN Authorization API 1.0 evaluation request and response: a '
        + 'subject, a resource, an action and a context, answered with a boolean `decision`. Two '
        + 'deviations, both stated rather than discovered. First, the path is realm scoped instead of '
        + 'a single global evaluation path, because a realm is this authority\'s trust boundary and a '
        + 'decision has no meaning outside one. Second, the response `context` carries the effect, '
        + 'the reason, the deciding policy with its version and statement position, and what each '
        + 'evaluator said on its own, which the specification permits as an extension and this '
        + 'authority requires: a decision a log cannot explain is not auditable, and a rule nobody '
        + 'can test is a rule that gets written wrong and stays wrong.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['resource', 'action'],
        additionalProperties: false,
        properties: {
          subject: {
            type: 'object',
            additionalProperties: false,
            description: 'Omitted means the caller. Naming somebody else requires the policy-reading tier.',
            properties: {
              type: { type: 'string', description: 'AuthZEN subject type. Recorded, not interpreted: this authority has one kind of principal.' },
              id: { type: 'string', minLength: 1 },
            },
          },
          resource: {
            type: 'object',
            required: ['type'],
            additionalProperties: false,
            properties: {
              type: { type: 'string', minLength: 1, description: 'The enforcement point\'s resource name, such as `roles`.' },
              id: { type: 'string', description: 'A particular instance. Recorded on the trace; no condition reads it today.' },
            },
          },
          action: {
            type: 'object',
            required: ['name'],
            additionalProperties: false,
            properties: { name: { type: 'string', minLength: 1, examples: ['view'] } },
          },
          context: {
            type: 'object',
            additionalProperties: false,
            description: 'Identity context only, matching the condition vocabulary a policy may use.',
            properties: {
              audience: { type: 'string', description: 'The resource server the roles are resolved against. Defaults to this authority\'s own.' },
              assuranceLevel: { type: 'string', enum: ['aal1', 'aal2', 'aal3'] },
              ip: { type: 'string' },
              tenantId: { type: 'string' },
              attestationState: { type: 'string', enum: ['attested', 'unattested'] },
            },
          },
        },
        examples: [{
          subject: { type: 'identity', id: 'a1000070-0000-4000-8000-000000000070' },
          resource: { type: 'roles' },
          action: { name: 'manage' },
          context: { assuranceLevel: 'aal1' },
        }],
      },
      response: {
        200: {
          description: 'The decision, and how it was reached.',
          type: 'object',
          additionalProperties: false,
          required: ['decision', 'context'],
          properties: {
            decision: { type: 'boolean', description: 'AuthZEN: true is permit, false is deny. Absence of a permit is a deny.' },
            context: {
              type: 'object',
              additionalProperties: false,
              required: ['effect', 'reason', 'evaluators'],
              properties: {
                effect: { type: 'string', enum: ['allow', 'deny'] },
                reason: { type: 'string', description: 'Why, in the words the deciding statement or role carries.' },
                source: { type: 'string', description: 'What decided: a policy as `name@version`, or `default-deny`.' },
                policy: {
                  type: 'object',
                  additionalProperties: false,
                  description: 'Present when a stored policy decided. Absent when a role or the default did.',
                  required: ['policyId', 'name', 'version', 'statementIndex', 'effect'],
                  properties: {
                    policyId: { type: 'string' },
                    name: { type: 'string' },
                    version: { type: 'string' },
                    statementIndex: { type: 'integer', description: 'Position in that policy\'s statement list, from zero.' },
                    effect: { type: 'string', enum: ['allow', 'deny'] },
                  },
                },
                evaluators: {
                  type: 'array',
                  description: 'What each evaluator said alone. A null effect is no opinion, which is not a denial.',
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    required: ['name', 'effect'],
                    properties: {
                      name: { type: 'string' },
                      // Null is a real value here, not an omission: it says the evaluator had no
                      // opinion, which is a different finding from a denial.
                      effect: { type: ['string', 'null'], enum: ['allow', 'deny', null] },
                      reason: { type: 'string' },
                      source: { type: 'string' },
                    },
                  },
                },
                subjectId: { type: 'string', description: 'Who the decision was about, echoed so a trace is unambiguous.' },
                evaluatedAt: { type: 'string' },
              },
            },
          },
          examples: [{
            decision: false,
            context: {
              effect: 'deny',
              reason: 'Changing what a role grants requires a second factor.',
              source: 'administration-requires-strong-authentication@1',
              policy: {
                policyId: '2b6f0a51-d8e4-4a11-9c2e-77d4a3f1e0c2',
                name: 'administration-requires-strong-authentication',
                version: '1',
                statementIndex: 0,
                effect: 'deny',
              },
              evaluators: [
                { name: 'abac', effect: 'deny', reason: 'Changing what a role grants requires a second factor.' },
                { name: 'rbac', effect: 'allow', reason: 'granted by realm_administrator' },
              ],
              subjectId: 'a1000070-0000-4000-8000-000000000070',
              evaluatedAt: '2026-08-31T09:12:00.000Z',
            },
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const body = request.body as {
      subject?: { type?: string; id?: string };
      resource: { type: string; id?: string };
      action: { name: string };
      context?: Record<string, unknown>;
    };

    const subjectId = body.subject?.id ?? caller.subjectId;
    if (subjectId !== caller.subjectId) {
      // Another subject's authority is information about them. Same tier as reading the policies.
      const gate = await administers(realm.realmId, caller.subjectId, 'policies', 'view');
      if ('refused' in gate) {
        return reply.status(403).send(problem(
          403,
          'Not permitted',
          'Evaluating a decision about another principal discloses what that principal may do. '
          + 'Ask about yourself, or hold the permission that reads this realm\'s policies.',
        ));
      }
    }

    const context = { ...(body.context ?? {}) };
    // Defaults to the authority's own resource server, which is what the roles screen grants against.
    context.audience ??= 'authority';
    context.tenantId ??= realm.tenantId;

    const traced = await new PolicyDecisionService().evaluate({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      subjectId,
      resource: body.resource.type,
      action: body.action.name,
      context,
    });

    // Recorded because an evaluation about somebody else is a read of their authority, and because a
    // simulator whose answers leave no trace is a way to probe a realm quietly.
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action: 'authorization.decision.evaluated',
      outcome: 'success',
      decision: traced.decision.effect,
      subjectId,
      clientId: caller.clientId,
      ...(traced.decision.policy ? { policyVersion: traced.decision.policy.version } : {}),
      detail: {
        askedBy: caller.subjectId,
        resource: body.resource.type,
        ...(body.resource.id ? { resourceId: body.resource.id } : {}),
        action: body.action.name,
        source: traced.decision.source,
      },
    });

    return reply.send({
      decision: traced.decision.effect === 'allow',
      context: {
        effect: traced.decision.effect,
        reason: traced.decision.reason,
        ...(traced.decision.source ? { source: traced.decision.source } : {}),
        ...(traced.decision.policy ? { policy: traced.decision.policy } : {}),
        evaluators: traced.evaluators,
        subjectId,
        evaluatedAt: new Date().toISOString(),
      },
    });
  });
}
