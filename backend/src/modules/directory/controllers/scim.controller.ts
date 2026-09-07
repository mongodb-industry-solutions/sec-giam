import { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requireAuthority } from '../../../vendors/middleware/authorityAuth';
import { PRINCIPAL_COLLECTION, ROLE_COLLECTION } from '../../../shared/models/collections';
import { PrincipalRecord } from '../models/principal.model';
import { newMeta } from '../../../shared/models/base.model';
import { provisioningTargets } from '../../../shared/ports';
import {
  toScimUser, toScimList, scimError, parseScimFilter, applyScimPatch,
  provisionedLifecycleState, SCIM_USER_SCHEMA,
} from '../services/scim.service';

/**
 * SCIM 2.0, so existing provisioning tooling works with no bespoke integration.
 *
 * The rule that shapes every route here: provisioning must not ACTIVATE. A create says a principal
 * exists; whether it may operate is a separate decision made somewhere else. A provisioning event
 * that silently confers operational capability turns a directory sync into a privilege escalation
 * path, and it is the failure mode this whole surface is arranged to prevent.
 *
 * A provisioning client also cannot grant authority. It may correct a name or deactivate somebody; it
 * may not assign a role. Otherwise whoever administers the upstream directory can grant themselves
 * anything here, which is the same defect as trusting upstream claims for authorisation.
 *
 * Who may reach these routes is decided by the caller's own roles, over the authority's `identities`
 * resource. The operator credential still passes, as break-glass, because an identity outage is
 * exactly when nobody can sign in to fix it. Listing the directory is never a self-scoped act, so
 * there is no owner path here the way there is for a client registration.
 */
export async function scimController(fastify: FastifyInstance) {
  const base = '/realms/:realm/scim/v2';

  function location(realm: string): string {
    return `/realms/${realm}/scim/v2`;
  }

  const scimUserSchema = {
    type: 'object',
    additionalProperties: true,
    required: ['schemas', 'id', 'userName', 'active'],
    properties: {
      schemas: { type: 'array', items: { type: 'string' } },
      id: { type: 'string' },
      externalId: { type: 'string' },
      userName: { type: 'string' },
      name: { type: 'object', additionalProperties: true },
      emails: { type: 'array', items: { type: 'object', additionalProperties: true } },
      active: { type: 'boolean' },
      meta: { type: 'object', additionalProperties: true },
    },
    examples: [{
      schemas: [SCIM_USER_SCHEMA],
      id: 'sub-9f21',
      userName: 'ada',
      active: true,
      meta: { resourceType: 'User', location: '/realms/acme/scim/v2/Users/sub-9f21' },
    }],
  } as const;

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /** Pushes a lifecycle change outward, and never lets a delivery failure undo the change. */
  async function notifyConsumers(operation: 'create' | 'update' | 'deactivate', subjectId: string, payload: Record<string, unknown>) {
    try {
      await provisioningTargets.resolve('webhook').push(operation, subjectId, payload);
    } catch {
      // Deliberately swallowed. A consumer that cannot be told must not be able to keep a suspended
      // principal active here.
    }
  }

  function identities() {
    return fastify.db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION);
  }

  /**
   * roleId to role name, for the whole response.
   *
   * Read ONCE per request rather than per principal: a page of a hundred people holding the same
   * handful of roles would otherwise be a hundred lookups of the same few documents. Empty on
   * failure, which publishes the ids rather than dropping the roles: an opaque value a reader can
   * still resolve is better than a person appearing to hold nothing.
   */
  async function roleNames(realmId: string): Promise<Map<string, string>> {
    try {
      const roles = await fastify.db
        .collection<{ roleId: string; name: string }>(ROLE_COLLECTION)
        .find({ realmId }, { projection: { _id: 0, roleId: 1, name: 1 } })
        .toArray();
      return new Map(roles.map((role) => [role.roleId, role.name]));
    } catch {
      return new Map();
    }
  }

  fastify.get(`${base}/Users`, {
    preHandler: requireAuthority('identities', 'view'),
    schema: {
      operationId: 'scimListUsers',
      tags: ['scim'],
      summary: 'List principals',
      description:
        'Standard-defined: SCIM 2.0, RFC 7644 section 3.4.2. Only `eq` filters on userName, '
        + 'externalId and active are supported, and anything else is REFUSED rather than partially '
        + 'interpreted: a mistranslated filter returns the wrong principals instead of an error, '
        + 'which is far worse than an honest refusal. `domainId` and `pending` are separate, '
        + 'platform-specific parameters rather than folded into `filter`, so the standard grammar '
        + 'stays exactly the standard grammar and neither narrowing is ever mistaken for part of it.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          filter: { type: 'string', examples: ['userName eq "ada"'] },
          domainId: { type: 'string', description: 'Principals provisioned through this authentication path.' },
          pending: { type: 'boolean', description: 'Self-registered principals awaiting approval.' },
          startIndex: { type: 'integer', default: 1, description: 'One-based, per the specification.' },
          count: { type: 'integer', default: 100 },
        },
      },
      response: {
        200: {
          description: 'A SCIM list response.',
          type: 'object',
          additionalProperties: true,
          required: ['schemas', 'Resources', 'totalResults'],
          properties: {
            schemas: { type: 'array', items: { type: 'string' } },
            totalResults: { type: 'integer' },
            startIndex: { type: 'integer' },
            itemsPerPage: { type: 'integer' },
            Resources: { type: 'array', items: scimUserSchema },
          },
          examples: [{
            schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
            totalResults: 1,
            startIndex: 1,
            itemsPerPage: 1,
            Resources: [scimUserSchema.examples[0]],
          }],
        },
        400: { type: 'object', additionalProperties: true, description: 'The filter is not supported.' },
        401: { type: 'object', additionalProperties: true, description: 'No access token and no operator credential.' },
        403: { type: 'object', additionalProperties: true, description: 'No role held permits administering the directory.' },
        404: { type: 'object', additionalProperties: true, description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const { filter, domainId, pending, startIndex, count } = request.query as {
      filter?: string; domainId?: string; pending?: boolean; startIndex?: number; count?: number;
    };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(scimError(404, 'No such realm'));

    const parsed = parseScimFilter(filter);
    if ('unsupported' in parsed) {
      return reply.status(400).send(scimError(400, `Unsupported filter: ${parsed.unsupported}`, 'invalidFilter'));
    }

    const from = Math.max(1, startIndex ?? 1);
    const limit = Math.min(count ?? 100, 200);
    const query = {
      realmId: realm.realmId,
      ...parsed,
      ...(domainId ? { domainId } : {}),
      ...(pending ? { lifecycleState: 'pending' as const } : {}),
    };

    const [records, total] = await Promise.all([
      identities().find(query, { projection: { _id: 0 } }).sort({ userName: 1 }).skip(from - 1).limit(limit).toArray(),
      identities().countDocuments(query),
    ]);

    const names = await roleNames(realm.realmId);
    return reply
      .header('content-type', 'application/scim+json')
      .send(toScimList(records.map((record) => toScimUser(record, location(realmName), names)), total, from));
  });

  fastify.get(`${base}/Users/:id`, {
    preHandler: requireAuthority('identities', 'view'),
    schema: {
      operationId: 'scimGetUser',
      tags: ['scim'],
      summary: 'One principal',
      description: 'Standard-defined: SCIM 2.0, RFC 7644 section 3.4.1.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id'],
        properties: { realm: { type: 'string' }, id: { type: 'string' } },
      },
      response: {
        200: { ...scimUserSchema, description: 'The principal.' },
        401: { type: 'object', additionalProperties: true, description: 'No access token and no operator credential.' },
        403: { type: 'object', additionalProperties: true, description: 'No role held permits administering the directory.' },
        404: { type: 'object', additionalProperties: true, description: 'No such principal.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id } = request.params as { realm: string; id: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(scimError(404, 'No such realm'));

    const record = await identities().findOne({ realmId: realm.realmId, subjectId: id }, { projection: { _id: 0 } });
    if (!record) return reply.status(404).send(scimError(404, 'No such principal'));

    return reply.header('content-type', 'application/scim+json').send(toScimUser(record, location(realmName), await roleNames(realm.realmId)));
  });

  fastify.post(`${base}/Users`, {
    preHandler: requireAuthority('identities', 'manage'),
    schema: {
      operationId: 'scimCreateUser',
      tags: ['scim'],
      summary: 'Provision a principal',
      description:
        'Standard-defined: SCIM 2.0, RFC 7644 section 3.3. The created principal is NOT activated '
        + 'unless the realm says new principals are auto-approved. Provisioning says a principal '
        + 'exists; something else says it may operate, and a create that silently granted operational '
        + 'capability would make a directory sync into a privilege escalation path.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['userName'],
        additionalProperties: true,
        properties: {
          schemas: { type: 'array', items: { type: 'string' } },
          userName: { type: 'string' },
          externalId: { type: 'string' },
          name: { type: 'object', additionalProperties: true },
          emails: { type: 'array', items: { type: 'object', additionalProperties: true } },
          active: { type: 'boolean' },
        },
      },
      response: {
        201: { ...scimUserSchema, description: 'The provisioned principal.' },
        401: { type: 'object', additionalProperties: true, description: 'No access token and no operator credential.' },
        403: { type: 'object', additionalProperties: true, description: 'No role held permits administering the directory.' },
        404: { type: 'object', additionalProperties: true, description: 'No such realm.' },
        409: { type: 'object', additionalProperties: true, description: 'That user name already exists.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as {
      userName: string; externalId?: string;
      name?: { formatted?: string; givenName?: string; familyName?: string };
      emails?: Array<{ value?: string; primary?: boolean }>;
    };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(scimError(404, 'No such realm'));

    if (await identities().findOne({ realmId: realm.realmId, userName: body.userName }, { projection: { _id: 0, subjectId: 1 } })) {
      return reply.status(409).send(scimError(409, 'That user name already exists', 'uniqueness'));
    }

    const primary = body.emails?.find((email) => email.primary) ?? body.emails?.[0];
    const now = new Date().toISOString();
    // Provisioning lands in the internal directory, so it is that path's approval rule that
    // decides whether the principal is usable at once (ADR-002).
    const { autoApprove } = await new RealmService(fastify.db).registration(realm.realmId);
    const lifecycleState = provisionedLifecycleState(autoApprove);

    const record = {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      subjectId: `sub-${randomUUID()}`,
      userName: body.userName,
      kind: 'human',
      ...(body.externalId ? { externalId: body.externalId } : {}),
      ...(body.name ? { name: body.name } : {}),
      ...(primary?.value ? { primaryEmail: String(primary.value).toLowerCase() } : {}),
      // The `active` a client sent is deliberately ignored. Whether a new principal may operate is
      // the realm's decision, not the provisioning client's.
      active: lifecycleState === 'active',
      lifecycleState,
      sessionEpoch: 0,
      meta: newMeta('Identity'),
    } as unknown as PrincipalRecord;

    await identities().insertOne(record);

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'identity.provisioned',
      outcome: 'success',
      subjectId: record.subjectId,
      detail: { via: 'scim', lifecycleState, externalId: body.externalId },
    });

    // Told to consumers, never awaited. A receiver that is down must not fail the provisioning, and
    // reconciliation is what corrects it.
    void notifyConsumers('create', record.subjectId, {
      realmId: realm.realmId,
      active: record.active,
      lifecycleState,
      userName: record.userName,
      version: record.meta.version,
    });

    return reply
      .status(201)
      .header('content-type', 'application/scim+json')
      .send(toScimUser(record, location(realmName), await roleNames(realm.realmId)));
  });

  fastify.patch(`${base}/Users/:id`, {
    preHandler: requireAuthority('identities', 'manage'),
    schema: {
      operationId: 'scimPatchUser',
      tags: ['scim'],
      summary: 'Change a principal',
      description:
        'Standard-defined: SCIM 2.0, RFC 7644 section 3.5.2. Only a short allowlist of attributes can '
        + 'be changed: a name, an email, an external id, and whether the principal is active. A '
        + 'provisioning client cannot grant authority, because otherwise whoever administers the '
        + 'upstream directory could grant themselves anything here.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id'],
        properties: { realm: { type: 'string' }, id: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['Operations'],
        additionalProperties: true,
        properties: {
          schemas: { type: 'array', items: { type: 'string' } },
          Operations: {
            type: 'array',
            items: {
              type: 'object',
              required: ['op'],
              additionalProperties: true,
              properties: { op: { type: 'string' }, path: { type: 'string' } },
            },
          },
        },
      },
      response: {
        200: { ...scimUserSchema, description: 'The principal, as changed.' },
        400: { type: 'object', additionalProperties: true, description: 'An operation or attribute is not permitted here.' },
        401: { type: 'object', additionalProperties: true, description: 'No access token and no operator credential.' },
        403: { type: 'object', additionalProperties: true, description: 'No role held permits administering the directory.' },
        404: { type: 'object', additionalProperties: true, description: 'No such principal.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id } = request.params as { realm: string; id: string };
    const { Operations } = request.body as { Operations: Array<{ op: string; path?: string; value?: unknown }> };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(scimError(404, 'No such realm'));

    const existing = await identities().findOne({ realmId: realm.realmId, subjectId: id }, { projection: { _id: 0 } });
    if (!existing) return reply.status(404).send(scimError(404, 'No such principal'));

    const update = applyScimPatch(Operations ?? []);
    if ('rejected' in update) return reply.status(400).send(scimError(400, String(update.rejected), 'noTarget'));

    // Deactivating through provisioning must actually END access, not merely mark a flag. Raising the
    // epoch retires every token already issued, including any this authority never recorded.
    const deactivating = update.active === false;
    /**
     * The other half of that same symmetry, added in v43.
     *
     * Self-registration without auto-approve lands a principal in `pending` with `active: false`
     * (`registration.controller.ts`). Before this, setting `active: true` on one left
     * `lifecycleState: 'pending'` untouched: the record ended up `active: true` and
     * `lifecycleState: 'pending'` AT ONCE, a state nothing else checked for, and there was no way
     * to correctly approve a pending account through provisioning at all.
     */
    const approving = update.active === true && existing.lifecycleState === 'pending';
    await identities().updateOne(
      { subjectId: id },
      {
        $set: {
          ...update,
          ...(deactivating ? { lifecycleState: 'suspended' } : {}),
          ...(approving ? { lifecycleState: 'active' } : {}),
          'meta.lastModified': new Date().toISOString(),
        },
        ...(deactivating ? { $inc: { sessionEpoch: 1 } } : {}),
      },
    );

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: deactivating ? 'identity.deactivated' : approving ? 'identity.approved' : 'identity.updated',
      outcome: 'success',
      subjectId: id,
      detail: { via: 'scim', changed: Object.keys(update) },
    });

    void notifyConsumers(deactivating ? 'deactivate' : 'update', id, {
      realmId: realm.realmId,
      active: update.active ?? existing.active,
      lifecycleState: deactivating ? 'suspended' : approving ? 'active' : existing.lifecycleState,
      version: (existing.meta?.version ?? 0) + 1,
    });

    const updated = await identities().findOne({ subjectId: id }, { projection: { _id: 0 } });
    return reply
      .header('content-type', 'application/scim+json')
      .send(toScimUser(updated as PrincipalRecord, location(realmName), await roleNames(realm.realmId)));
  });

  fastify.delete(`${base}/Users/:id`, {
    preHandler: requireAuthority('identities', 'manage'),
    schema: {
      operationId: 'scimDeleteUser',
      tags: ['scim'],
      summary: 'Deprovision a principal',
      description:
        'Standard-defined: SCIM 2.0, RFC 7644 section 3.6. The record is retired rather than deleted. '
        + 'A principal that is gone leaves an audit trail referring to an identifier nothing can '
        + 'resolve, and "who was that" is exactly the question asked after an incident.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id'],
        properties: { realm: { type: 'string' }, id: { type: 'string' } },
      },
      response: {
        204: { description: 'Retired.' },
        401: {
          type: 'object',
          additionalProperties: true,
          description: 'No access token and no operator credential.',
          examples: [{ schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'], status: '401', detail: 'A valid access token or the operator credential is required.' }],
        },
        403: { type: 'object', additionalProperties: true, description: 'No role held permits administering the directory.' },
        404: { type: 'object', additionalProperties: true, description: 'No such principal.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id } = request.params as { realm: string; id: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(scimError(404, 'No such realm'));

    const result = await identities().updateOne(
      { realmId: realm.realmId, subjectId: id },
      {
        $set: { active: false, lifecycleState: 'deprovisioned', 'meta.lastModified': new Date().toISOString() },
        // Everything outstanding stops working now rather than running to expiry.
        $inc: { sessionEpoch: 1 },
      },
    );
    if (result.matchedCount === 0) return reply.status(404).send(scimError(404, 'No such principal'));

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'identity.deprovisioned',
      outcome: 'success',
      subjectId: id,
      detail: { via: 'scim' },
    });

    void notifyConsumers('deactivate', id, {
      realmId: realm.realmId,
      active: false,
      lifecycleState: 'deprovisioned',
    });

    return reply.status(204).send();
  });
}
