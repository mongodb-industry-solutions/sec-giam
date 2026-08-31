import { FastifyInstance } from 'fastify';
import { randomUUID, randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';
import { RealmService } from '../../realm/services/realm.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';
import { ClientRecord } from '../models/client.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Registering an application, so a consumer never holds a client secret it minted itself.
 *
 * The onboarding flow in a consuming application keeps its shape from the operator's point of view:
 * approve a merchant, get credentials. What changes is who generates them. The consumer holds the
 * commercial record and the returned client id; the authority holds the credential, and it is the
 * only party that ever sees the secret in the clear.
 *
 * That matters for a reason beyond tidiness. A consumer that generates client secrets has a
 * credential store, a hashing decision and a rotation policy, and it will get one of those subtly
 * wrong in a way nobody notices until the audit.
 */
export async function clientRegistrationController(fastify: FastifyInstance) {
  const base = '/realms/:realm/clients';

  const clientView = {
    type: 'object',
    additionalProperties: true,
    required: ['client_id', 'client_name'],
    properties: {
      client_id: { type: 'string' },
      client_name: { type: 'string' },
      client_secret: {
        type: 'string',
        description: 'Returned ONCE, at registration or rotation, and never retrievable afterwards.',
      },
      redirect_uris: { type: 'array', items: { type: 'string' } },
      grant_types: { type: 'array', items: { type: 'string' } },
      scope: { type: 'string' },
      logo_uri: { type: 'string' },
      status: { type: 'string' },
    },
    examples: [{
      client_id: 'acme-portal',
      client_name: 'Acme Portal',
      redirect_uris: ['https://acme.example/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile',
      status: 'active',
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  function clients() {
    return fastify.db.collection<ClientRecord>(CLIENT_COLLECTION);
  }

  /**
   * A secret is shown once and stored only as a hash.
   *
   * Anything else means the authority can hand somebody's credential back to whoever asks next, and
   * "we can look it up for you" is indistinguishable from "anyone who reaches this can have it".
   */
  async function mintSecret(): Promise<{ secret: string; hash: string }> {
    const secret = randomBytes(32).toString('base64url');
    return { secret, hash: await bcrypt.hash(secret, 12) };
  }

  fastify.post(base, {
    preHandler: requireAdmin,
    schema: {
      operationId: 'registerClient',
      tags: ['oauth'],
      summary: 'Register an application',
      description:
        'Standard-defined: RFC 7591 dynamic client registration. The secret is generated here and '
        + 'returned once. A consuming application that generated its own would need a credential '
        + 'store, a hashing decision and a rotation policy of its own, and would get one of them '
        + 'subtly wrong.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['client_name'],
        additionalProperties: true,
        properties: {
          client_name: { type: 'string' },
          redirect_uris: { type: 'array', items: { type: 'string' } },
          grant_types: { type: 'array', items: { type: 'string' } },
          scope: { type: 'string' },
          logo_uri: { type: 'string' },
          /** The consumer's own record for whoever owns this client. Opaque here. */
          owner_ref: { type: 'string' },
        },
      },
      response: {
        201: { ...clientView, description: 'The registered client, with its secret, once.' },
        401: { $ref: 'Problem#', description: 'No registration credential.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That client name is already registered here.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as {
      client_name: string; redirect_uris?: string[]; grant_types?: string[];
      scope?: string; logo_uri?: string; owner_ref?: string;
    };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const clientId = `cli-${randomUUID()}`;
    const { secret, hash } = await mintSecret();
    const isPublic = (body.grant_types ?? []).every((grant) => grant === 'authorization_code');

    await clients().insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      clientId,
      clientName: body.client_name,
      type: isPublic ? 'public' : 'confidential',
      clientSecretHash: hash,
      redirectUris: body.redirect_uris ?? [],
      grantTypes: body.grant_types ?? ['client_credentials'],
      scope: body.scope ?? 'openid',
      ...(body.logo_uri ? { logoUri: body.logo_uri } : {}),
      ...(body.owner_ref ? { owner: { kind: 'tenant', ref: body.owner_ref } } : {}),
      requirePkce: true,
      status: 'active',
      meta: newMeta('Client'),
    } as unknown as ClientRecord);

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'client.registered',
      outcome: 'success',
      clientId,
      detail: { clientName: body.client_name, ownerRef: body.owner_ref },
    });

    return reply.status(201).send({
      client_id: clientId,
      client_name: body.client_name,
      // The one and only time this value leaves the authority.
      client_secret: secret,
      redirect_uris: body.redirect_uris ?? [],
      grant_types: body.grant_types ?? ['client_credentials'],
      scope: body.scope ?? 'openid',
      status: 'active',
    });
  });

  fastify.patch(`${base}/:clientId`, {
    preHandler: requireAdmin,
    schema: {
      operationId: 'updateClient',
      tags: ['oauth'],
      summary: 'Change a registered application',
      description:
        'Standard-defined: RFC 7592 client configuration. Changes the registration; never returns or '
        + 'changes the secret, which has its own route so that rotating a credential is always a '
        + 'deliberate act rather than a side effect of editing a redirect URI.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: true,
        properties: {
          client_name: { type: 'string' },
          redirect_uris: { type: 'array', items: { type: 'string' } },
          scope: { type: 'string' },
          logo_uri: { type: 'string' },
        },
      },
      response: {
        200: { ...clientView, description: 'The client, as changed. No secret.' },
        401: { $ref: 'Problem#', description: 'No registration credential.' },
        404: { $ref: 'Problem#', description: 'No such client.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const body = request.body as Record<string, unknown>;

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const update: Record<string, unknown> = {};
    if (body.client_name) update.clientName = body.client_name;
    if (body.redirect_uris) update.redirectUris = body.redirect_uris;
    if (body.scope) update.scope = body.scope;
    if (body.logo_uri) update.logoUri = body.logo_uri;

    const result = await clients().updateOne(
      { realmId: realm.realmId, clientId },
      { $set: { ...update, 'meta.lastModified': new Date().toISOString() } },
    );
    if (result.matchedCount === 0) return reply.status(404).send(problem(404, 'No such client'));

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'client.updated',
      outcome: 'success',
      clientId,
      detail: { changed: Object.keys(update) },
    });

    const updated = await clients().findOne(
      { clientId },
      { projection: { _id: 0, clientSecretHash: 0 } },
    ) as ClientRecord | null;
    return reply.send({
      client_id: clientId,
      client_name: updated?.clientName,
      redirect_uris: updated?.redirectUris ?? [],
      grant_types: updated?.grantTypes ?? [],
      scope: updated?.scope,
      status: updated?.status,
    });
  });

  fastify.post(`${base}/:clientId/rotate-secret`, {
    preHandler: requireAdmin,
    schema: {
      operationId: 'rotateClientSecret',
      tags: ['oauth'],
      summary: 'Issue a new secret for an application',
      description:
        'Standard-adjacent: the credential half of RFC 7592. The previous secret stops working '
        + 'immediately. There is no overlap window, because two live secrets means a compromised one '
        + 'keeps working for the length of that window, which is exactly when it must not.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      response: {
        200: { ...clientView, description: 'The client, with its new secret, once.' },
        401: { $ref: 'Problem#', description: 'No registration credential.' },
        404: { $ref: 'Problem#', description: 'No such client.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const { secret, hash } = await mintSecret();
    const result = await clients().updateOne(
      { realmId: realm.realmId, clientId },
      { $set: { clientSecretHash: hash, 'meta.lastModified': new Date().toISOString() } },
    );
    if (result.matchedCount === 0) return reply.status(404).send(problem(404, 'No such client'));

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'client.secret_rotated',
      outcome: 'success',
      clientId,
    });

    return reply.send({ client_id: clientId, client_name: '', client_secret: secret, status: 'active' });
  });

  fastify.delete(`${base}/:clientId`, {
    preHandler: requireAdmin,
    schema: {
      operationId: 'revokeClient',
      tags: ['oauth'],
      summary: 'Withdraw an application',
      description:
        'Standard-defined: RFC 7592 deletion. The registration is marked revoked rather than removed, '
        + 'so an audit trail naming this client still resolves. Nothing it holds keeps working: the '
        + 'credential stops authenticating immediately.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      response: {
        // Answered with the withdrawn registration rather than an empty 204, so a caller can confirm
        // what it just withdrew without a second read.
        200: { ...clientView, description: 'The registration, now withdrawn.' },
        401: { $ref: 'Problem#', description: 'No registration credential.' },
        404: { $ref: 'Problem#', description: 'No such client.' },
        503: { $ref: 'Problem#', description: 'The administrative surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const result = await clients().updateOne(
      { realmId: realm.realmId, clientId },
      {
        // The hash is dropped as well as the status changed. A revoked client whose secret is still
        // stored is a credential waiting for somebody to reactivate the record.
        $set: { status: 'revoked', 'meta.lastModified': new Date().toISOString() },
        $unset: { clientSecretHash: '' },
      },
    );
    if (result.matchedCount === 0) return reply.status(404).send(problem(404, 'No such client'));

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'client.revoked',
      outcome: 'success',
      clientId,
    });

    return reply.send({ client_id: clientId, client_name: '', status: 'revoked' });
  });
}
