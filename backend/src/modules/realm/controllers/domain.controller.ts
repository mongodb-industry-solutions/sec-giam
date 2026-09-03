import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { RealmService } from '../services/realm.service';
import { DomainRecord } from '../models/domain.model';
import { DOMAIN_COLLECTION } from '../../../shared/models/collections';
import { authorityAccess, refusal } from '../../authorization/services/authorityAccess';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Administering the authentication paths of a realm. ADR-002.
 *
 * ADR-001 made `domain` a collection and moved the realm's authentication configuration onto it,
 * and nothing was ever built to administer it. The console has had a complete domain surface all
 * along, calling a route that existed in no service, and it failed silently because every caller
 * wraps the request in a catch and renders an empty list.
 *
 * Authorised on `providers`, not on a new permission. A domain IS an authentication provider in
 * this model, which is what `providerId` and the sign-in context's `providers` already call it, and
 * inventing `domains:*` would add a permission nobody holds to describe something an existing pair
 * describes correctly.
 *
 * WHAT IS PUBLISHED IS AN ALLOWLIST. `config` carries an open index signature, so a generous read
 * is a credential disclosure waiting to happen: `clientSecretRef` names a secret today and nothing
 * stops an adapter writing a bind password beside it tomorrow. An allowlist that has not heard of a
 * new setting withholds it, and a missing field in an admin screen is a bug report while a leaked
 * credential is an incident.
 */

/** The settings a console may see. Everything else in `config` is dropped on the way out. */
const PUBLISHED_CONFIG = [
  'issuer',
  'clientId',
  'authorizationEndpoint',
  'tokenEndpoint',
  'jwksUri',
  'scopes',
  'tenant',
  'emailDomains',
] as const;

function publishedConfig(config: DomainRecord['config']): Record<string, unknown> {
  const shown: Record<string, unknown> = {};
  for (const key of PUBLISHED_CONFIG) {
    if (config?.[key] !== undefined) shown[key] = config[key];
  }
  return shown;
}

function view(domain: DomainRecord) {
  return {
    providerId: domain.providerId,
    name: domain.name,
    displayName: domain.displayName,
    protocol: domain.protocol,
    adapter: domain.adapter,
    enabled: domain.enabled,
    ...(domain.notice ? { notice: domain.notice } : {}),
    config: publishedConfig(domain.config),
    claimMappings: domain.claimMappings ?? [],
    ...(domain.authentication ? { authentication: domain.authentication } : {}),
    ...(domain.session ? { session: domain.session } : {}),
    ...(domain.registration ? { registration: domain.registration } : {}),
    /**
     * Whether a secret is configured, WITHOUT naming or revealing it.
     *
     * A console has to be able to say "this provider has no secret yet", which is the difference
     * between a provider that is misconfigured and one that is merely disabled. That question is
     * answerable with a boolean, so it is answered with a boolean.
     */
    hasClientSecret: Boolean(domain.config?.clientSecretRef),
    createdAt: domain.meta?.created,
    lastModifiedAt: domain.meta?.lastModified,
  };
}

export async function domainController(fastify: FastifyInstance) {
  const base = '/realms/:realm/domains';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const domainParams = {
    type: 'object',
    required: ['realm', 'providerId'],
    properties: { realm: { type: 'string' }, providerId: { type: 'string' } },
  } as const;

  /**
   * The published shape, documented with an example.
   *
   * `additionalProperties: true` deliberately: Fastify STRIPS anything a response schema does not
   * declare, so a strict schema here would silently drop `authentication`, `session` or
   * `registration` from the answer depending on which path it described. The example is what the
   * contract test asks for, and it is also the quickest way for a reader to see the vocabulary.
   */
  const domainView = {
    type: 'object',
    additionalProperties: true,
    example: {
      providerId: 'a4c610e1-65c0-5e4c-813c-4cb9712a8bcf',
      name: 'atlas-id',
      displayName: 'Acme directory',
      protocol: 'internal',
      adapter: 'internal',
      enabled: true,
      config: {},
      claimMappings: [],
      registration: { selfServiceEnabled: true, autoApprove: false },
      hasClientSecret: false,
    },
  } as const;

  const listView = {
    type: 'object',
    additionalProperties: true,
    example: {
      items: [domainView.example],
      total: 1,
      page: 1,
      limit: 50,
    },
  } as const;

  function domains() {
    return fastify.db.collection<DomainRecord>(DOMAIN_COLLECTION);
  }

  /** The caller, the realm, and whether they may act on it. Resolved once per request. */
  async function reach(request: FastifyRequest, reply: FastifyReply, action: 'view' | 'manage') {
    const { realm: realmName } = request.params as { realm: string };
    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) {
      await reply.status(404).send(problem(404, 'Unknown realm'));
      return null;
    }

    const subjectId = (request as unknown as { principal?: { subjectId?: string } }).principal?.subjectId ?? '';
    const access = await authorityAccess(fastify.db, realm.realmId, subjectId);
    if (!access.can('providers', action)) {
      await reply.status(403).send(refusal('providers', action));
      return null;
    }
    return { realm, subjectId };
  }

  function audit(
    realm: { realmId: string; tenantId: string },
    subjectId: string,
    input: { action: string; outcome: 'success' | 'failure'; providerId?: string; cause?: string; detail?: Record<string, unknown> },
  ): void {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: input.action,
      outcome: input.outcome,
      subjectId,
      ...(input.providerId ? { target: { type: 'domain', ref: input.providerId } } : {}),
      ...(input.cause ? { cause: input.cause } : {}),
      ...(input.detail ? { detail: input.detail } : {}),
    });
  }

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listDomains',
      tags: ['realms'],
      summary: 'Authentication paths of this realm',
      description:
        '**No applicable standard.** Every way a person can prove who they are in this realm. '
        + 'Provider settings are published through an allowlist, so no secret or secret reference '
        + 'appears here.',
      security: [{ bearerAuth: [] }],
      response: {
        200: { ...listView, description: 'The authentication paths of this realm.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held carries the provider permission.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          q: { type: 'string', description: 'Matches the name or the display name.' },
          page: { type: 'integer', minimum: 1, default: 1 },
          limit: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
        },
      },
    },
  }, async (request, reply) => {
    const reached = await reach(request, reply, 'view');
    if (!reached) return reply;

    const { q, page, limit } = request.query as { q?: string; page?: number; limit?: number };
    const at = Math.max(1, page ?? 1);
    const size = Math.min(limit ?? 50, 200);
    // Escaped: a name is free text, and an unescaped one turns a search box into a regex console.
    const filter = {
      realmId: reached.realm.realmId,
      ...(q
        ? { $or: [
          { name: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
          { displayName: { $regex: q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' } },
        ] }
        : {}),
    };

    const [records, total] = await Promise.all([
      domains().find(filter, { projection: { _id: 0 } }).sort({ name: 1 }).skip((at - 1) * size).limit(size).toArray(),
      domains().countDocuments(filter),
    ]);

    return reply.send({ items: records.map(view), total, page: at, limit: size });
  });

  fastify.get(`${base}/:providerId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getDomain',
      tags: ['realms'],
      summary: 'One authentication path',
      description: '**No applicable standard.** One authentication path, with its settings allowlisted.',
      security: [{ bearerAuth: [] }],
      response: {
        200: { ...domainView, description: 'One authentication path.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held carries the provider permission.' },
        404: { $ref: 'Problem#', description: 'No such realm or domain.' },
      },
      params: domainParams,
    },
  }, async (request, reply) => {
    const reached = await reach(request, reply, 'view');
    if (!reached) return reply;

    const { providerId } = request.params as { providerId: string };
    const record = await domains().findOne({ realmId: reached.realm.realmId, providerId }, { projection: { _id: 0 } });
    if (!record) return reply.status(404).send(problem(404, 'No such domain'));
    return reply.send(view(record));
  });

  const writableBody = {
    type: 'object',
    additionalProperties: false,
    properties: {
      name: { type: 'string', minLength: 1, description: 'Slug, unique inside the realm.' },
      displayName: { type: 'string', minLength: 1 },
      protocol: { type: 'string', enum: ['internal', 'oidc', 'saml', 'ldap', 'spiffe'] },
      adapter: { type: 'string' },
      enabled: { type: 'boolean' },
      notice: { type: 'string' },
      config: { type: 'object', additionalProperties: true },
      claimMappings: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['claim', 'value', 'roleName'],
          properties: { claim: { type: 'string' }, value: { type: 'string' }, roleName: { type: 'string' } },
        },
      },
      registration: {
        type: 'object',
        additionalProperties: false,
        required: ['selfServiceEnabled', 'autoApprove'],
        properties: { selfServiceEnabled: { type: 'boolean' }, autoApprove: { type: 'boolean' } },
      },
      session: {
        type: 'object',
        additionalProperties: false,
        required: ['maxConcurrent', 'onExceed'],
        properties: {
          maxConcurrent: { type: ['integer', 'null'], minimum: 1 },
          onExceed: { type: 'string', enum: ['evict-oldest', 'refuse-new'] },
        },
      },
    },
  } as const;

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'createDomain',
      tags: ['realms'],
      summary: 'Add an authentication path',
      description:
        '**No applicable standard.** Created DISABLED, so it authenticates nobody before its '
        + 'settings have been checked.',
      security: [{ bearerAuth: [] }],
      response: {
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held carries the provider permission.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That name is already used in this realm.' },
        201: { ...domainView, description: 'The path as created, which is disabled.' },
      },
      params: realmParam,
      body: { ...writableBody, required: ['name', 'displayName', 'protocol'] },
    },
  }, async (request, reply) => {
    const reached = await reach(request, reply, 'manage');
    if (!reached) return reply;

    const body = request.body as Partial<DomainRecord> & { name: string; displayName: string; protocol: DomainRecord['protocol'] };

    // The slug is what a sign-in screen and home-realm discovery both resolve on, so a duplicate
    // would make which path answers depend on document order.
    if (await domains().findOne({ realmId: reached.realm.realmId, name: body.name }, { projection: { _id: 1 } })) {
      audit(reached.realm, reached.subjectId, { action: 'domain.created', outcome: 'failure', cause: 'name_taken' });
      return reply.status(409).send(problem(409, 'That name is already used in this realm'));
    }

    const providerId = uuidv4();
    const record: DomainRecord = {
      realmId: reached.realm.realmId,
      tenantId: reached.realm.tenantId,
      providerId,
      name: body.name,
      displayName: body.displayName,
      protocol: body.protocol,
      // Defaults to the protocol's own adapter: an operator adding an OIDC provider should not have
      // to know the name of the code that handles it.
      adapter: body.adapter ?? body.protocol,
      // Disabled unless asked for. A path that authenticates people the moment it is created, before
      // anybody has checked its settings, is the wrong default.
      enabled: body.enabled ?? false,
      ...(body.notice ? { notice: body.notice } : {}),
      config: body.config ?? {},
      claimMappings: body.claimMappings ?? [],
      ...(body.registration ? { registration: body.registration } : {}),
      ...(body.session ? { session: body.session } : {}),
      meta: newMeta('Domain'),
    };

    await domains().insertOne(record);
    audit(reached.realm, reached.subjectId, { action: 'domain.created', outcome: 'success', providerId, detail: { name: body.name, protocol: body.protocol } });
    return reply.status(201).send(view(record));
  });

  fastify.patch(`${base}/:providerId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'updateDomain',
      tags: ['realms'],
      summary: 'Change an authentication path',
      description:
        '**No applicable standard.** Only the named fields can be changed. `config` is MERGED '
        + 'rather than replaced, so a console that never received a secret reference cannot drop it '
        + 'by sending back what it saw.',
      security: [{ bearerAuth: [] }],
      response: {
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held carries the provider permission.' },
        404: { $ref: 'Problem#', description: 'No such realm or domain.' },
        409: { $ref: 'Problem#', description: 'The name is taken, or this is the last enabled path.' },
        200: { ...domainView, description: 'The path as it now stands.' },
      },
      params: domainParams,
      body: writableBody,
    },
  }, async (request, reply) => {
    const reached = await reach(request, reply, 'manage');
    if (!reached) return reply;

    const { providerId } = request.params as { providerId: string };
    const body = request.body as Partial<DomainRecord>;
    const existing = await domains().findOne({ realmId: reached.realm.realmId, providerId }, { projection: { _id: 0 } });
    if (!existing) return reply.status(404).send(problem(404, 'No such domain'));

    if (body.name && body.name !== existing.name) {
      if (await domains().findOne({ realmId: reached.realm.realmId, name: body.name }, { projection: { _id: 1 } })) {
        return reply.status(409).send(problem(409, 'That name is already used in this realm'));
      }
    }

    // Turning off the last enabled path locks everybody out, including whoever would turn it back on.
    if (body.enabled === false && existing.enabled) {
      const enabled = await domains().countDocuments({ realmId: reached.realm.realmId, enabled: true });
      if (enabled <= 1) {
        audit(reached.realm, reached.subjectId, { action: 'domain.updated', outcome: 'failure', providerId, cause: 'last_enabled_path' });
        return reply.status(409).send(problem(
          409,
          'This is the only way in',
          'Disabling the last enabled authentication path would leave nobody able to sign in, including you.',
        ));
      }
    }

    const changes: Record<string, unknown> = { 'meta.lastModified': new Date().toISOString() };
    for (const field of ['name', 'displayName', 'protocol', 'adapter', 'enabled', 'notice', 'claimMappings', 'registration', 'session'] as const) {
      if (body[field] !== undefined) changes[field] = body[field];
    }
    /**
     * `config` is merged key by key, never assigned wholesale.
     *
     * The read publishes an allowlist, so a console round-tripping what it was given would send
     * back a config with `clientSecretRef` missing, and a wholesale write would then delete the
     * provider's secret reference as a side effect of saving an unrelated field.
     */
    for (const [key, value] of Object.entries(body.config ?? {})) {
      changes[`config.${key}`] = value;
    }

    await domains().updateOne({ realmId: reached.realm.realmId, providerId }, { $set: changes });
    const updated = await domains().findOne({ realmId: reached.realm.realmId, providerId }, { projection: { _id: 0 } });
    audit(reached.realm, reached.subjectId, {
      action: 'domain.updated',
      outcome: 'success',
      providerId,
      // The FIELDS that changed, never their values: a claim mapping or an issuer is configuration,
      // and a trail that copies configuration is a trail that eventually copies a secret.
      detail: { changed: Object.keys(changes).filter((key) => key !== 'meta.lastModified') },
    });
    return reply.send(view(updated as DomainRecord));
  });

  fastify.delete(`${base}/:providerId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'deleteDomain',
      tags: ['realms'],
      summary: 'Remove an authentication path',
      description:
        '**No applicable standard.** Refused when it is the last enabled path, which would leave '
        + 'the realm unreachable, including by whoever would undo it.',
      security: [{ bearerAuth: [] }],
      response: {
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held carries the provider permission.' },
        404: { $ref: 'Problem#', description: 'No such realm or domain.' },
        409: { $ref: 'Problem#', description: 'This is the last enabled authentication path.' },
        200: {
          type: 'object',
          additionalProperties: false,
          properties: { deleted: { type: 'boolean' } },
          example: { deleted: true },
          description: 'The path is gone.',
        },
      },
      params: domainParams,
    },
  }, async (request, reply) => {
    const reached = await reach(request, reply, 'manage');
    if (!reached) return reply;

    const { providerId } = request.params as { providerId: string };
    const existing = await domains().findOne({ realmId: reached.realm.realmId, providerId }, { projection: { _id: 0 } });
    if (!existing) return reply.status(404).send(problem(404, 'No such domain'));

    if (existing.enabled) {
      const enabled = await domains().countDocuments({ realmId: reached.realm.realmId, enabled: true });
      if (enabled <= 1) {
        audit(reached.realm, reached.subjectId, { action: 'domain.deleted', outcome: 'failure', providerId, cause: 'last_enabled_path' });
        return reply.status(409).send(problem(
          409,
          'This is the only way in',
          'Deleting the last enabled authentication path would leave nobody able to sign in, including you.',
        ));
      }
    }

    await domains().deleteOne({ realmId: reached.realm.realmId, providerId });
    audit(reached.realm, reached.subjectId, { action: 'domain.deleted', outcome: 'success', providerId, detail: { name: existing.name } });
    return reply.send({ deleted: true });
  });
}
