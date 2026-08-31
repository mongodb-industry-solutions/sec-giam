import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, readClientCredentials } from '../../oauth/services/clientAuth.service';
import { BackchannelService, isFailure, BACKCHANNEL_GRANT } from '../services/backchannel.service';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';
import { ClientRecord } from '../../oauth/models/client.model';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';

/**
 * Backchannel authentication, the routes a client and an approving device use.
 *
 * The client asks here; the device fetches the challenge, signs it and posts the result. The token
 * endpoint is where the tokens come from, unchanged, because this is a way of authenticating and not
 * a second authorization server.
 */
export async function backchannelController(fastify: FastifyInstance) {
  const base = '/realms/:realm/protocol/openid-connect/ext/ciba';

  function fail(reply: never | { status: (code: number) => { send: (body: unknown) => unknown } }, status: number, error: string, description?: string) {
    return reply.status(status).send({ error, ...(description ? { error_description: description } : {}) });
  }

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const challengeResponse = {
    description: 'What the approving device shows and signs.',
    type: 'object',
    additionalProperties: false,
    required: ['auth_req_id', 'challenge', 'client_id', 'scopes', 'status'],
    properties: {
      auth_req_id: { type: 'string' },
      challenge: { type: 'string' },
      binding_message: { type: 'string' },
      client_id: { type: 'string' },
      client_name: { type: 'string' },
      scopes: { type: 'array', items: { type: 'string' } },
      status: { type: 'string' },
    },
    examples: [{
      auth_req_id: '5f1b…',
      challenge: 'Yk8s…',
      binding_message: 'Approve sign-in at Acme',
      client_id: 'acme-portal',
      client_name: 'Acme Portal',
      scopes: ['openid'],
      status: 'pending',
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  async function clientName(clientId: string): Promise<string> {
    const client = await fastify.db.collection<ClientRecord>(CLIENT_COLLECTION)
      .findOne({ clientId }, { projection: { _id: 0, clientName: 1 } });
    return client?.clientName ?? clientId;
  }

  // ── The client asks ─────────────────────────────────────────────────────────
  fastify.post(`${base}/auth`, {
    schema: {
      operationId: 'initiateBackchannelAuthentication',
      tags: ['authentication'],
      summary: 'Ask a principal to approve, out of band',
      description:
        'Standard-defined: OpenID Connect Client-Initiated Backchannel Authentication Core 1.0. The '
        + 'client authenticates as itself and names the principal by hint. No browser and no password '
        + 'is involved: approval happens on a device that signs the returned challenge.',
      security: [{ clientBasic: [] }, {}],
      consumes: ['application/x-www-form-urlencoded'],
      params: realmParam,
      body: {
        type: 'object',
        additionalProperties: true,
        properties: {
          scope: { type: 'string', examples: ['openid'] },
          login_hint: { type: 'string' },
          login_hint_token: { type: 'string' },
          id_token_hint: { type: 'string' },
          binding_message: { type: 'string', description: 'Shown on the device, so the person can tell which request they are approving.' },
          requested_expiry: { type: 'integer' },
          client_notification_token: { type: 'string' },
          client_id: { type: 'string' },
          client_secret: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'The pending request.',
          type: 'object',
          additionalProperties: false,
          required: ['auth_req_id', 'expires_in', 'interval'],
          properties: {
            auth_req_id: { type: 'string' },
            expires_in: { type: 'integer' },
            interval: { type: 'integer' },
          },
          examples: [{ auth_req_id: '5f1b…', expires_in: 300, interval: 5 }],
        },
        400: { $ref: 'OAuthError#', description: 'The request or the hint is invalid.' },
        401: { $ref: 'OAuthError#', description: 'Client authentication failed.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as Record<string, unknown>;

    const realm = await realmOf(realmName);
    if (!realm || !realm.enabled) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    const clientAuth = new ClientAuthService(fastify.db);
    const outcome = await clientAuth.authenticate(
      realm.realmId,
      readClientCredentials(request.headers.authorization, body),
      { requireAuthentication: true },
    );
    if ('error' in outcome) return fail(reply as never, 401, outcome.error, outcome.description);
    const { client } = outcome;

    if (!clientAuth.allowsGrant(client, BACKCHANNEL_GRANT)) {
      return fail(reply as never, 400, 'unauthorized_client', 'this client is not registered for that grant');
    }

    const result = await new BackchannelService(fastify.db).initiate(realm, client, {
      scope: body.scope as string | undefined,
      loginHint: body.login_hint as string | undefined,
      loginHintToken: body.login_hint_token as string | undefined,
      idTokenHint: body.id_token_hint as string | undefined,
      bindingMessage: body.binding_message as string | undefined,
      requestedExpiry: body.requested_expiry ? Number(body.requested_expiry) : undefined,
      clientNotificationToken: body.client_notification_token as string | undefined,
    });
    if (isFailure(result)) return fail(reply as never, result.status, result.error, result.description);
    return reply.send(result);
  });

  // ── The device asks what is waiting for its owner ───────────────────────────
  fastify.get(`${base}/auth/pending`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listPendingBackchannelRequests',
      tags: ['authentication'],
      summary: 'Approvals waiting for the calling principal',
      description:
        'OpenID Connect Client-Initiated Backchannel Authentication Core 1.0, the device-facing half. '
        + 'Scoped to the CALLER: an approving device shows its owner what is waiting for them, and this '
        + 'cannot be used to discover what anybody else has been asked to approve.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'What is waiting, newest first.',
          type: 'object',
          additionalProperties: false,
          required: ['pending'],
          properties: { pending: { type: 'array', items: challengeResponse } },
          examples: [{ pending: [challengeResponse.examples[0]] }],
        },
        401: { $ref: 'OAuthError#', description: 'No valid access token.' },
        404: { $ref: 'OAuthError#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return fail(reply as never, 404, 'invalid_request', 'unknown realm');

    const waiting = await new BackchannelService(fastify.db).pending(realm.realmId, caller.subjectId);
    return reply.send({ pending: waiting });
  });

  // ── The device fetches what it must sign ────────────────────────────────────
  fastify.get(`${base}/auth/:authReqId`, {
    schema: {
      operationId: 'getBackchannelChallenge',
      tags: ['authentication'],
      summary: 'The challenge for a pending request',
      description:
        'OpenID Connect Client-Initiated Backchannel Authentication Core 1.0, the device-facing half, '
        + 'which the specification leaves to the '
        + 'provider. Public by design: holding the identifier lets a device see what it would be '
        + 'signing, and approval still requires the private key. Nothing here is a secret.',
      security: [],
      params: {
        type: 'object',
        required: ['realm', 'authReqId'],
        properties: { realm: { type: 'string' }, authReqId: { type: 'string' } },
      },
      response: {
        200: challengeResponse,
        400: { $ref: 'OAuthError#', description: 'The request has expired.' },
        404: { $ref: 'OAuthError#', description: 'No such request.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, authReqId } = request.params as { realm: string; authReqId: string };
    const realm = await realmOf(realmName);
    if (!realm) return fail(reply as never, 404, 'invalid_request', 'unknown realm');

    const view = await new BackchannelService(fastify.db).challenge(realm.realmId, authReqId, clientName);
    if (isFailure(view)) return fail(reply as never, view.status, view.error, view.description);
    return reply.send(view);
  });

  // ── The device approves ─────────────────────────────────────────────────────
  fastify.post(`${base}/auth/:authReqId/approve`, {
    schema: {
      operationId: 'approveBackchannelRequest',
      tags: ['authentication'],
      summary: 'Approve, by signing the challenge',
      description:
        'OpenID Connect Client-Initiated Backchannel Authentication Core 1.0, the device-facing half. '
        + 'The signature over the challenge IS the '
        + 'authentication, so no session and no password is involved. The key must belong to the '
        + 'principal the request named.',
      security: [],
      params: {
        type: 'object',
        required: ['realm', 'authReqId'],
        properties: { realm: { type: 'string' }, authReqId: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['credentialId', 'signature'],
        additionalProperties: false,
        properties: {
          credentialId: { type: 'string', description: 'Which registered authenticator signed.' },
          signature: { type: 'string', description: 'base64url signature over the challenge.' },
        },
      },
      response: {
        200: {
          description: 'Approved.',
          type: 'object',
          additionalProperties: false,
          required: ['status'],
          properties: { status: { type: 'string' } },
          examples: [{ status: 'approved' }],
        },
        400: { $ref: 'OAuthError#', description: 'The request is no longer pending.' },
        401: { $ref: 'OAuthError#', description: 'The proof did not verify.' },
        404: { $ref: 'OAuthError#', description: 'No such request.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, authReqId } = request.params as { realm: string; authReqId: string };
    const realm = await realmOf(realmName);
    if (!realm) return fail(reply as never, 404, 'invalid_request', 'unknown realm');

    const service = new BackchannelService(fastify.db);
    const result = await service.approve(realm, authReqId, request.body as { credentialId: string; signature: string });
    if (isFailure(result)) return fail(reply as never, result.status, result.error, result.description);

    // ping tells the client to come and collect. push is handled at redemption, where the tokens
    // exist; minting them here would produce a token set before anything claimed the request.
    const client = await fastify.db.collection<ClientRecord>(CLIENT_COLLECTION)
      .findOne({ realmId: realm.realmId, clientId: result.clientId }, { projection: { _id: 0 } });
    if (client?.backchannel?.deliveryMode === 'ping') void service.notify(client, authReqId);

    return reply.send({ status: result.status });
  });

  // ── The device refuses ──────────────────────────────────────────────────────
  fastify.post(`${base}/auth/:authReqId/deny`, {
    schema: {
      operationId: 'denyBackchannelRequest',
      tags: ['authentication'],
      summary: 'Refuse a pending request',
      description:
        'OpenID Connect Client-Initiated Backchannel Authentication Core 1.0, the device-facing half. '
        + 'A refusal is authorised the same way an '
        + 'approval is, because otherwise anyone who saw an identifier could cancel another '
        + "person's sign-in.",
      security: [],
      params: {
        type: 'object',
        required: ['realm', 'authReqId'],
        properties: { realm: { type: 'string' }, authReqId: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          credentialId: { type: 'string' },
          signature: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'Denied.',
          type: 'object',
          additionalProperties: false,
          required: ['status'],
          properties: { status: { type: 'string' } },
          examples: [{ status: 'denied' }],
        },
        400: { $ref: 'OAuthError#', description: 'The request is no longer pending.' },
        401: { $ref: 'OAuthError#', description: 'The refusal was not authorised.' },
        404: { $ref: 'OAuthError#', description: 'No such request.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, authReqId } = request.params as { realm: string; authReqId: string };
    const realm = await realmOf(realmName);
    if (!realm) return fail(reply as never, 404, 'invalid_request', 'unknown realm');

    const result = await new BackchannelService(fastify.db)
      .deny(realm, authReqId, (request.body ?? {}) as { credentialId?: string; signature?: string });
    if (isFailure(result)) return fail(reply as never, result.status, result.error, result.description);
    return reply.send(result);
  });
}
