import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { PolicyAdminService, isPolicyRefusal } from '../services/policyAdmin.service';
import { PolicyDecisionService } from '../services/policyDecision.service';
import { RoleAdminService } from '../services/roleAdmin.service';
import { ResourceAdminService } from '../services/resourceAdmin.service';
import { authorityAccess, refusal } from '../services/authorityAccess';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal, requirePrincipalAtHome } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

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
    description:
      'Identity context only: assurance, network, time, tenant, attestation, and what the subject '
      + 'already holds (role membership, specific permissions). Nothing else may be expressed.',
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
      heldRole: {
        type: 'array', minItems: 1, items: { type: 'string' },
        description: 'The subject must hold at least one of these roles, by name. Any one of them satisfies it.',
      },
      heldPermission: {
        type: 'array', minItems: 1, items: { type: 'string' },
        description: 'The subject must hold every one of these permissions, `resource:action`. Independent of heldRole: either, neither or both may be named.',
      },
    },
  } as const;

  /** What a policy obliges the ENFORCING side to do. Carried here, acted on there. */
  const obligationSchema = {
    type: 'object',
    additionalProperties: false,
    required: ['type'],
    properties: {
      type: { type: 'string' },
      severity: { type: 'string', enum: ['low', 'medium', 'high'] },
    },
  } as const;

  /**
   * One way of naming "one or several things", used identically for `resource`, `permission`,
   * `principal` and `role`. `ids` is the fast path: named exactly, matched by a plain indexed
   * lookup. `pattern` is a regular expression, for the rare policy that describes a shape rather
   * than listing every member it covers; it is compiled with RE2, not the language's own regex
   * engine, so an author's pattern is guaranteed linear-time and cannot make a decision hang the
   * way a catastrophic-backtracking pattern could. `ids` wins when both are given, rather than the
   * write being refused: a pattern left beside a more specific `ids` list is dead weight, not a
   * contradiction worth rejecting.
   */
  const selectorSchema = {
    type: 'object',
    additionalProperties: false,
    properties: {
      ids: { type: 'array', minItems: 1, items: { type: 'string', minLength: 1 } },
      pattern: { type: 'string', minLength: 1, description: 'A regular expression, compiled with RE2. `ids` wins if both are given.' },
    },
  } as const;

  const policyBody = {
    effect: { type: 'string', enum: ['allow', 'deny'], description: 'Deny wins over every allow, absolutely.' },
    resource: { ...selectorSchema, description: 'What this policy governs, by resource id or by pattern.' },
    permission: {
      ...selectorSchema,
      description:
        'The permissions this author added directly, `resource:action` (the same spelling a role and '
        + 'a token use). Combined with what `role` below grants, if anything does, into what this '
        + 'policy actually covers.',
    },
    role: {
      ...selectorSchema,
      description:
        'Roles whose CURRENT, expanded permissions (parents included) are folded into what this '
        + 'policy covers, resolved once when this policy is saved and again whenever a named role '
        + 'changes shape. A convenience for building a permission set out of what a role already '
        + 'grants, not a second targeting axis: the decision engine never reads this field, only the '
        + 'permissions it resolved to.',
    },
    principal: { ...selectorSchema, description: 'Who this governs, by subject id or by pattern. Absent matches anyone.' },
    conditions: {
      type: 'array',
      items: conditionSchema,
      description: 'ALL must hold. Any-of would mean adding a condition could widen a policy.',
    },
    obligations: { type: 'array', items: obligationSchema },
    approvedBy: { type: 'string' },
    effectiveFrom: { type: 'string', description: 'Written down and not yet in force until this moment passes.' },
    reason: { type: 'string', description: 'Carried into the decision. A decision a log cannot explain is not auditable.' },
  } as const;

  const policySummary = {
    type: 'object',
    additionalProperties: false,
    required: ['policyId', 'name', 'version', 'status', 'effect', 'resource', 'permissionCount', 'conditionCount', 'inEffect'],
    properties: {
      policyId: { type: 'string' },
      name: { type: 'string' },
      // `PolicyRecord.version` is a number, incremented per revision. Declared `string` here would
      // silently mis-type every list and detail response against its own published contract.
      version: { type: 'integer' },
      status: { type: 'string', enum: ['draft', 'active', 'retired'] },
      effect: { type: 'string', enum: ['allow', 'deny'], description: 'Whether this policy prohibits. The first thing a reviewer wants to know.' },
      resource: selectorSchema,
      permissionCount: { type: 'integer', description: '`resolvedPermissions.length`: what this policy concretely covers right now, roles expanded.' },
      conditionCount: { type: 'integer' },
      inEffect: { type: 'boolean', description: 'False while drafted, retired, or dated ahead.' },
      created: { type: 'string' },
      lastModified: { type: 'string' },
    },
    examples: [{
      policyId: '2b6f0a51-d8e4-4a11-9c2e-77d4a3f1e0c2',
      name: 'administration-requires-strong-authentication',
      version: 1,
      status: 'active',
      effect: 'deny',
      resource: { ids: ['roles'] },
      permissionCount: 1,
      conditionCount: 1,
      inEffect: true,
    }],
  } as const;

  const policyDetail = {
    type: 'object',
    additionalProperties: false,
    required: [...policySummary.required, 'permission', 'resolvedPermissions', 'conditions'],
    properties: {
      ...policySummary.properties,
      ...policyBody,
      resolvedPermissions: {
        type: 'array',
        items: { type: 'string' },
        description:
          'The actual, flat set of `resource:action` strings this policy is evaluated against: '
          + '`permission.ids` union every permission every role in `role` currently grants. Read-only: '
          + 'computed from `permission` and `role`, never accepted directly.',
      },
    },
    /**
     * The FLAT shape, which is what the endpoint returns.
     *
     * This was the v39 `statements: [{ actions, resources, condition }]` form, so it satisfied
     * neither the required members (`permission`, `resource`, `conditions`) nor
     * `additionalProperties: false`. Showing a shape v40 removed is worse than showing none:
     * somebody reads the contract, writes a client against `statements`, and finds out at
     * integration time.
     */
    examples: [{
      ...policySummary.examples[0],
      permission: { ids: ['roles:manage'] },
      resolvedPermissions: ['roles:manage'],
      resource: { ids: ['roles'] },
      conditions: [{ assuranceAtLeast: 'aal2' }],
      reason: 'Changing what a role grants requires a second factor.',
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
      tags: ['policies'],
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
          status: { type: 'string', enum: ['draft', 'active', 'retired'] },
          governs: {
            type: 'string',
            description:
              'Only policies whose resource selector actually matches this resource name, by exact '
              + 'name or by pattern. What a resource\'s own screen asks to show which policies govern it. '
              + 'Several names may be given, separated by commas, matching a policy that governs ANY '
              + 'of them: a resource server is never named by a policy directly, so its own page asks '
              + 'with the names of every resource type it declares.',
          },
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

    const { q, status, governs, skip, limit } = request.query as {
      q?: string; status?: 'draft' | 'active' | 'retired'; governs?: string; skip?: number; limit?: number;
    };
    return reply.send(await new PolicyAdminService(fastify.db).list(realm.realmId, { q, status, governs, skip, limit }));
  });

  fastify.get(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getPolicy',
      tags: ['policies'],
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

  /**
   * Which of this realm's own resources this policy actually governs, resolved the same way a
   * decision is: `resourceApplies` against the resource catalog, not a second, approximate idea of
   * what `names`/`pattern` mean. A `names` policy's own list is trivially every match; a `pattern`
   * one has no list at all until this runs it against every registered resource, which is the
   * entire reason this is its own read rather than a field on the policy's own document.
   */
  fastify.get(`${base}/:policyId/resources`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listPolicyResources',
      tags: ['policies'],
      summary: 'Which resources this policy actually governs',
      description:
        'No applicable standard. Every resource in this realm\'s own catalog that this policy\'s '
        + '`resource` selector matches, exact name or pattern, resolved with the identical '
        + '`resourceApplies` the decision engine uses. Not paged: a realm\'s resource catalog is the '
        + 'kind of thing read whole, the same reasoning `/permissions` and `/resource-servers` follow.',
      security: [{ bearerAuth: [] }],
      params: policyParams,
      response: {
        200: {
          description: 'The resources this policy currently matches.',
          type: 'object',
          additionalProperties: false,
          required: ['resources', 'total'],
          properties: {
            resources: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                required: ['resourceId', 'name', 'status'],
                properties: {
                  resourceId: { type: 'string' },
                  name: { type: 'string' },
                  status: { type: 'string', enum: ['active', 'deprecated', 'withdrawn'] },
                },
              },
            },
            total: { type: 'integer' },
          },
          examples: [{ resources: [{ resourceId: 'b2d5…', name: 'reports', status: 'active' }], total: 1 }],
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

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'policies', 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    const detail = await new PolicyAdminService(fastify.db).detail(realm.realmId, policyId);
    if (!detail) return reply.status(404).send(problem(404, 'No such policy'));

    const resources = await new ResourceAdminService(fastify.db).matching(realm.realmId, detail.resource);
    return reply.send({ resources, total: resources.length });
  });

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'createPolicy',
      tags: ['policies'],
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
        required: ['name', 'effect', 'resource'],
        additionalProperties: false,
        properties: {
          name: { type: 'string', minLength: 1, pattern: '^[a-zA-Z0-9._-]+$' },
          ...policyBody,
          status: { type: 'string', enum: ['draft', 'active', 'retired'], default: 'active' },
          version: { type: 'integer', minimum: 1, default: 1 },
        },
      },
      response: {
        201: { ...policyDetail, description: 'The policy as stated.' },
        400: { $ref: 'Problem#', description: 'The policy names a condition this authority cannot evaluate.' },
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

    const body = request.body as Parameters<PolicyAdminService['create']>[2];
    const outcome = await new PolicyAdminService(fastify.db).create(realm.realmId, realm.tenantId, body);
    if (isPolicyRefusal(outcome)) return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.policy.created', caller.subjectId, {
      policyId: outcome.policyId, name: outcome.name, effect: outcome.effect,
    });
    return reply.status(201).send(outcome);
  });

  fastify.patch(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'updatePolicy',
      tags: ['policies'],
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
          ...policyBody,
          status: { type: 'string', enum: ['draft', 'active', 'retired'] },
          version: { type: 'integer', minimum: 1 },
        },
      },
      response: {
        200: { ...policyDetail, description: 'The policy, as it now stands.' },
        400: { $ref: 'Problem#', description: 'The policy names a condition this authority cannot evaluate.' },
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

    const outcome = await new PolicyAdminService(fastify.db).update(realm.realmId, policyId, caller.subjectId, realm.tenantId, request.body as object);
    if (outcome === null) return reply.status(404).send(problem(404, 'No such policy'));
    if (isPolicyRefusal(outcome)) return reply.status(outcome.status as 400).send(problem(outcome.status, outcome.title, outcome.detail));

    audit(realm, 'authorization.policy.updated', caller.subjectId, {
      policyId, fields: Object.keys(request.body ?? {}), status: outcome.status,
    });
    return reply.send(outcome);
  });

  fastify.delete(`${base}/:policyId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'deletePolicy',
      tags: ['policies'],
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

  interface DecisionSpec {
    subject?: { type?: string; id?: string };
    resource: { type: string; id?: string };
    action: { name: string };
    context?: Record<string, unknown>;
  }

  type DecisionRefusal = { status: number; title: string; detail: string };

  /**
   * One evaluation, whether it arrived alone or as one entry of a batch.
   *
   * Factored out so `/decision` and its batch sibling can never quietly diverge: the same subject
   * gate, the same context defaults, the same evaluator and the same audit record either way. A
   * consumer asking the same question through either route gets the same answer for the same reason.
   */
  async function evaluateOne(
    realm: { realmId: string; tenantId: string },
    caller: { subjectId: string; clientId: string },
    spec: DecisionSpec,
  ): Promise<
    | { decision: boolean; context: Record<string, unknown> }
    | DecisionRefusal
  > {
    const subjectId = spec.subject?.id ?? caller.subjectId;
    if (subjectId !== caller.subjectId) {
      // Another subject's authority is information about them. Same tier as reading the policies.
      const gate = await administers(realm.realmId, caller.subjectId, 'policies', 'view');
      if ('refused' in gate) {
        return {
          status: 403,
          title: 'Not permitted',
          detail:
            'Evaluating a decision about another principal discloses what that principal may do. '
            + 'Ask about yourself, or hold the permission that reads this realm\'s policies.',
        };
      }
    }

    const context = { ...(spec.context ?? {}) };
    // Defaults to the authority's own resource server, which is what the roles screen grants against.
    context.audience ??= 'authority';
    context.tenantId ??= realm.tenantId;

    const traced = await new PolicyDecisionService().evaluate({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      subjectId,
      resource: spec.resource.type,
      action: spec.action.name,
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
        resource: spec.resource.type,
        ...(spec.resource.id ? { resourceId: spec.resource.id } : {}),
        action: spec.action.name,
        source: traced.decision.source,
      },
    });

    return {
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
    };
  }

  function isDecisionRefusal(value: unknown): value is DecisionRefusal {
    return typeof value === 'object' && value !== null && 'status' in value && 'title' in value;
  }

  /**
   * The four AuthZEN request fragments, named once so the single endpoint and the batch endpoint
   * describe the same `subject`/`resource`/`action`/`context` rather than two copies that could
   * drift. `resource` and `action` are required standalone (the single endpoint's own body needs
   * them); the batch endpoint relaxes that by wrapping them, not by declaring a second shape.
   */
  const decisionSubjectSchema = {
    type: 'object',
    additionalProperties: false,
    description: 'Omitted means the caller. Naming somebody else requires the policy-reading tier.',
    properties: {
      type: { type: 'string', description: 'AuthZEN subject type. Recorded, not interpreted: this authority has one kind of principal.' },
      id: { type: 'string', minLength: 1 },
    },
  } as const;

  const decisionResourceSchema = {
    type: 'object',
    required: ['type'],
    additionalProperties: false,
    properties: {
      type: { type: 'string', minLength: 1, description: 'The enforcement point\'s resource name, such as `roles`.' },
      id: { type: 'string', description: 'A particular instance. Recorded on the trace; no condition reads it today.' },
    },
  } as const;

  const decisionActionSchema = {
    type: 'object',
    required: ['name'],
    additionalProperties: false,
    properties: { name: { type: 'string', minLength: 1, examples: ['view'] } },
  } as const;

  const decisionContextSchema = {
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
  } as const;

  /** One decision's answer, named once so the single and the batch response can never disagree. */
  const decisionResponseSchema = {
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
            required: ['policyId', 'name', 'version', 'effect'],
            properties: {
              policyId: { type: 'string' },
              name: { type: 'string' },
              version: { type: 'integer', description: 'Which revision of the policy decided.' },
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
          version: 1,
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
  } as const;

  fastify.post('/realms/:realm/decision', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'evaluateDecision',
      tags: ['decision'],
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
          subject: decisionSubjectSchema,
          resource: decisionResourceSchema,
          action: decisionActionSchema,
          context: decisionContextSchema,
        },
        examples: [{
          subject: { type: 'identity', id: 'a1000070-0000-4000-8000-000000000070' },
          resource: { type: 'roles' },
          action: { name: 'manage' },
          context: { assuranceLevel: 'aal1' },
        }],
      },
      response: {
        200: { ...decisionResponseSchema, description: 'The decision, and how it was reached.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const outcome = await evaluateOne(realm, caller, request.body as DecisionSpec);
    if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
    return reply.send(outcome);
  });

  /**
   * AuthZEN 1.0's batch evaluation, `/access/v1/evaluations` in the specification's own naming.
   *
   * One request, many questions, answered in the order asked: the shape a screen rendering several
   * gated controls at once actually needs, instead of one round trip per control. A `subject`,
   * `resource`, `action` or `context` given at the top level is the DEFAULT for every entry that
   * does not name its own, exactly as the specification defines it; nothing here invents a second
   * meaning for the same fields the single endpoint already uses.
   *
   * Each entry is evaluated through the identical `evaluateOne` the single endpoint calls, so a
   * question asked here and the same question asked alone can never receive a different answer for
   * different reasons. A subject other than the caller is gated once for the whole batch rather than
   * once per entry: the permission that discloses another principal's authority does not become
   * cheaper to bypass by asking about them a hundred times in one request.
   */
  fastify.post('/realms/:realm/decision/evaluations', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'evaluateDecisions',
      tags: ['decision'],
      summary: 'Evaluate several authorization decisions in one call',
      description:
        'AuthZEN 1.0\'s batch evaluation extension. A `subject`, `resource`, `action` or `context` '
        + 'named at the top level is the default for every entry in `evaluations` that omits it. '
        + 'Answered in the same order asked, one `decision` per entry, each carrying this '
        + 'authority\'s own extended trace exactly as the single `/decision` endpoint does.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['evaluations'],
        additionalProperties: false,
        properties: {
          subject: decisionSubjectSchema,
          resource: decisionResourceSchema,
          action: decisionActionSchema,
          context: decisionContextSchema,
          evaluations: {
            type: 'array',
            minItems: 1,
            maxItems: 50,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                subject: decisionSubjectSchema,
                resource: decisionResourceSchema,
                action: decisionActionSchema,
                context: decisionContextSchema,
              },
            },
          },
        },
        examples: [{
          subject: { type: 'identity', id: 'a1000070-0000-4000-8000-000000000070' },
          evaluations: [
            { resource: { type: 'roles' }, action: { name: 'view' } },
            { resource: { type: 'roles' }, action: { name: 'manage' } },
          ],
        }],
      },
      response: {
        200: {
          description: 'One decision per entry, in the order asked.',
          type: 'object',
          additionalProperties: false,
          required: ['evaluations'],
          properties: {
            evaluations: {
              type: 'array',
              items: decisionResponseSchema,
            },
          },
          examples: [{
            evaluations: [
              {
                decision: true,
                context: {
                  effect: 'allow',
                  reason: 'granted by realm_administrator',
                  evaluators: [{ name: 'rbac', effect: 'allow', reason: 'granted by realm_administrator' }],
                  subjectId: 'a1000070-0000-4000-8000-000000000070',
                  evaluatedAt: '2026-08-31T09:12:00.000Z',
                },
              },
              decisionResponseSchema.examples[0],
            ],
          }],
        },
        400: { $ref: 'Problem#', description: 'An entry names no resource and action, and none is given as a default.' },
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
      subject?: DecisionSpec['subject'];
      resource?: DecisionSpec['resource'];
      action?: DecisionSpec['action'];
      context?: DecisionSpec['context'];
      evaluations: Array<Partial<DecisionSpec>>;
    };

    const specs: Array<DecisionSpec | null> = body.evaluations.map((entry) => {
      const resource = entry.resource ?? body.resource;
      const action = entry.action ?? body.action;
      if (!resource || !action) return null;
      return {
        subject: entry.subject ?? body.subject,
        resource,
        action,
        context: { ...(body.context ?? {}), ...(entry.context ?? {}) },
      };
    });

    const missing = specs.findIndex((spec) => spec === null);
    if (missing !== -1) {
      return reply.status(400).send(problem(
        400,
        'Incomplete evaluation',
        `Entry ${missing} names no \`resource\` and \`action\`, and none is given as a default at the top level.`,
      ));
    }

    // Sequential, not `Promise.all`: each entry is checked against the SAME oversight gate as the
    // single endpoint the moment it names a different subject, and running fifty of those
    // concurrently would fan out fifty simultaneous permission checks for one caller's one request.
    const outcomes: Array<{ decision: boolean; context: Record<string, unknown> }> = [];
    for (const spec of specs as DecisionSpec[]) {
      const outcome = await evaluateOne(realm, caller, spec);
      if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
      outcomes.push(outcome);
    }

    return reply.send({ evaluations: outcomes });
  });

  /**
   * AuthZEN 1.0's `/access/v1/search/action` extension: not "may X do Y", but "which Y may X do".
   *
   * Answerable honestly here in a way the other two search extensions in the specification are not.
   * The action dimension is a closed, declared catalog (`resource.actions[]`, the same one a role can
   * only ever be granted from), so enumerating it costs one read; searching over every SUBJECT or
   * every RESOURCE INSTANCE this authority knows about would not stay one read, and worse, a context-
   * dependent condition (an assurance floor, a time window) can only be evaluated for a request that
   * actually carries a context, which a reverse search over subjects or resources has none of. This
   * endpoint keeps the real context the caller supplied and asks the ordinary decision engine once
   * per declared action, so its answer is exactly as correct as the single endpoint's, never a
   * cheaper approximation that ignores a condition to make the search possible.
   */
  fastify.post('/realms/:realm/decision/search/action', {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'searchActions',
      tags: ['decision'],
      summary: 'Which actions a subject may take on a resource',
      description:
        'AuthZEN 1.0\'s `/access/v1/search/action` extension. Only the resource\'s DECLARED actions '
        + 'are considered, the same catalog a role can only ever be granted from, and each is asked '
        + 'through the identical decision path the single and batch endpoints use, with the SAME '
        + 'context: nothing here is answered by a cheaper approximation that drops a condition to '
        + 'make a reverse search possible.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['resource'],
        additionalProperties: false,
        properties: {
          subject: decisionSubjectSchema,
          resource: decisionResourceSchema,
          context: decisionContextSchema,
        },
        examples: [{
          subject: { type: 'identity', id: 'a1000070-0000-4000-8000-000000000070' },
          resource: { type: 'roles' },
        }],
      },
      response: {
        200: {
          description: 'The actions this resource declares that the subject may currently take.',
          type: 'object',
          additionalProperties: false,
          required: ['actions'],
          properties: {
            actions: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: { type: 'string' } } } },
          },
          examples: [{ actions: [{ name: 'view' }] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
        404: { $ref: 'Problem#', description: 'No such realm, or no such resource type declared.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const body = request.body as { subject?: DecisionSpec['subject']; resource: DecisionSpec['resource']; context?: DecisionSpec['context'] };
    const caller = request.principal!;

    const catalog = await new RoleAdminService(fastify.db).catalog(realm.realmId);
    const declared = catalog.filter((entry) => entry.resource === body.resource.type).map((entry) => entry.action);
    if (declared.length === 0) return reply.status(404).send(problem(404, 'No such resource type declared'));

    const allowed: string[] = [];
    // Sequential for the same reason the batch endpoint is: the oversight gate for a named subject
    // must run at most once conceptually, not race across N concurrent calls for one request.
    for (const action of [...new Set(declared)].sort()) {
      const outcome = await evaluateOne(realm, caller, { subject: body.subject, resource: body.resource, action: { name: action }, context: body.context });
      if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
      if (outcome.decision) allowed.push(action);
    }

    return reply.send({ actions: allowed.map((name) => ({ name })) });
  });

  /**
   * Compatibility aliases for the three decision endpoints above, at a path shaped for a generic
   * AuthZEN 1.0 client rather than this realm-scoped one, under this deployment's own `/api/v1`
   * prefix rather than the specification's own `/access/v1`.
   *
   * AuthZEN's base spec has no realm concept, so these use `requirePrincipalAtHome` instead of
   * `requirePrincipal`: the realm evaluated is always the caller's own, resolved from the token
   * itself, never a realm named in a path segment because there is none here. A caller who needs to
   * reach a SECOND realm still has to use the realm-scoped path above, where that crossing is
   * explicit and the grant behind it is auditable; this alias exists for interoperability with
   * clients that only know the specification's shape, not to offer a quieter way to cross realms.
   *
   * Everything else, request shape, response shape, evaluation, the audit record, is identical:
   * each alias calls the exact same `evaluateOne` (or the same per-entry loop) the realm-scoped
   * route above does, so a client that switched from one path to the other could not tell the
   * difference in behaviour.
   */
  async function realmOfCaller(principalRealmId: string): Promise<{ realmId: string; tenantId: string } | null> {
    const realm = await new RealmService(fastify.db).byId(principalRealmId);
    return realm && realm.enabled !== false ? { realmId: realm.realmId, tenantId: realm.tenantId } : null;
  }

  fastify.post('/access/evaluation', {
    preHandler: requirePrincipalAtHome,
    schema: {
      operationId: 'evaluateDecisionAtHome',
      tags: ['decision'],
      summary: 'Evaluate one authorization decision, at the AuthZEN-shaped compatibility path',
      description:
        'The same evaluation as `POST /api/v1/realms/:realm/decision`, at a path shaped for a generic '
        + 'AuthZEN 1.0 client rather than named to one realm. There is no realm segment because the '
        + 'specification has none: the realm evaluated is always the caller\'s own, resolved from '
        + 'the token that authenticated the request.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        required: ['resource', 'action'],
        additionalProperties: false,
        properties: {
          subject: decisionSubjectSchema,
          resource: decisionResourceSchema,
          action: decisionActionSchema,
          context: decisionContextSchema,
        },
        examples: [{ resource: { type: 'roles' }, action: { name: 'manage' } }],
      },
      response: {
        200: { ...decisionResponseSchema, description: 'The decision, and how it was reached.' },
        401: { $ref: 'Problem#', description: 'No valid access token, or the realm it belongs to is no longer enabled.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOfCaller(caller.realmId);
    if (!realm) return reply.status(401).send(problem(401, 'Unauthorized', 'The realm this token belongs to is no longer enabled.'));

    const outcome = await evaluateOne(realm, caller, request.body as DecisionSpec);
    if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
    return reply.send(outcome);
  });

  fastify.post('/access/evaluations', {
    preHandler: requirePrincipalAtHome,
    schema: {
      operationId: 'evaluateDecisionsAtHome',
      tags: ['decision'],
      summary: 'Evaluate several authorization decisions in one call, at the AuthZEN-shaped compatibility path',
      description:
        'The same batch evaluation as `POST /api/v1/realms/:realm/decision/evaluations`, at the path shaped '
        + 'for a generic AuthZEN 1.0 client. See that endpoint.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        required: ['evaluations'],
        additionalProperties: false,
        properties: {
          subject: decisionSubjectSchema,
          resource: decisionResourceSchema,
          action: decisionActionSchema,
          context: decisionContextSchema,
          evaluations: {
            type: 'array',
            minItems: 1,
            maxItems: 50,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                subject: decisionSubjectSchema,
                resource: decisionResourceSchema,
                action: decisionActionSchema,
                context: decisionContextSchema,
              },
            },
          },
        },
        examples: [{ evaluations: [{ resource: { type: 'roles' }, action: { name: 'view' } }] }],
      },
      response: {
        200: {
          description: 'One decision per entry, in the order asked.',
          type: 'object',
          additionalProperties: false,
          required: ['evaluations'],
          properties: { evaluations: { type: 'array', items: decisionResponseSchema } },
          examples: [{ evaluations: [decisionResponseSchema.examples[0]] }],
        },
        400: { $ref: 'Problem#', description: 'An entry names no resource and action, and none is given as a default.' },
        401: { $ref: 'Problem#', description: 'No valid access token, or the realm it belongs to is no longer enabled.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOfCaller(caller.realmId);
    if (!realm) return reply.status(401).send(problem(401, 'Unauthorized', 'The realm this token belongs to is no longer enabled.'));

    const body = request.body as {
      subject?: DecisionSpec['subject'];
      resource?: DecisionSpec['resource'];
      action?: DecisionSpec['action'];
      context?: DecisionSpec['context'];
      evaluations: Array<Partial<DecisionSpec>>;
    };

    const specs: Array<DecisionSpec | null> = body.evaluations.map((entry) => {
      const resource = entry.resource ?? body.resource;
      const action = entry.action ?? body.action;
      if (!resource || !action) return null;
      return {
        subject: entry.subject ?? body.subject,
        resource,
        action,
        context: { ...(body.context ?? {}), ...(entry.context ?? {}) },
      };
    });

    const missing = specs.findIndex((spec) => spec === null);
    if (missing !== -1) {
      return reply.status(400).send(problem(
        400,
        'Incomplete evaluation',
        `Entry ${missing} names no \`resource\` and \`action\`, and none is given as a default at the top level.`,
      ));
    }

    const outcomes: Array<{ decision: boolean; context: Record<string, unknown> }> = [];
    for (const spec of specs as DecisionSpec[]) {
      const outcome = await evaluateOne(realm, caller, spec);
      if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
      outcomes.push(outcome);
    }

    return reply.send({ evaluations: outcomes });
  });

  fastify.post('/access/search/action', {
    preHandler: requirePrincipalAtHome,
    schema: {
      operationId: 'searchActionsAtHome',
      tags: ['decision'],
      summary: 'Which actions a subject may take on a resource, at the AuthZEN-shaped compatibility path',
      description:
        'The same reverse search as `POST /api/v1/realms/:realm/decision/search/action`, at the path shaped '
        + 'for a generic AuthZEN 1.0 client. See that endpoint.',
      security: [{ bearerAuth: [] }],
      body: {
        type: 'object',
        required: ['resource'],
        additionalProperties: false,
        properties: { subject: decisionSubjectSchema, resource: decisionResourceSchema, context: decisionContextSchema },
        examples: [{ resource: { type: 'roles' } }],
      },
      response: {
        200: {
          description: 'The actions this resource declares that the subject may currently take.',
          type: 'object',
          additionalProperties: false,
          required: ['actions'],
          properties: {
            actions: { type: 'array', items: { type: 'object', additionalProperties: false, required: ['name'], properties: { name: { type: 'string' } } } },
          },
          examples: [{ actions: [{ name: 'view' }] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token, or the realm it belongs to is no longer enabled.' },
        403: { $ref: 'Problem#', description: 'Asking about another subject without the tier that reads policies.' },
        404: { $ref: 'Problem#', description: 'No such resource type declared.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOfCaller(caller.realmId);
    if (!realm) return reply.status(401).send(problem(401, 'Unauthorized', 'The realm this token belongs to is no longer enabled.'));

    const body = request.body as { subject?: DecisionSpec['subject']; resource: DecisionSpec['resource']; context?: DecisionSpec['context'] };

    const catalog = await new RoleAdminService(fastify.db).catalog(realm.realmId);
    const declared = catalog.filter((entry) => entry.resource === body.resource.type).map((entry) => entry.action);
    if (declared.length === 0) return reply.status(404).send(problem(404, 'No such resource type declared'));

    const allowed: string[] = [];
    for (const action of [...new Set(declared)].sort()) {
      const outcome = await evaluateOne(realm, caller, { subject: body.subject, resource: body.resource, action: { name: action }, context: body.context });
      if (isDecisionRefusal(outcome)) return reply.status(outcome.status as 403).send(problem(outcome.status, outcome.title, outcome.detail));
      if (outcome.decision) allowed.push(action);
    }

    return reply.send({ actions: allowed.map((name) => ({ name })) });
  });
}
