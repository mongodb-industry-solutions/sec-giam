import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { EnrollmentService, isEnrollmentFailure, RegisterInput } from '../services/enrollment.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';

/**
 * Registering and retiring authenticators.
 *
 * Every route is the caller's own: the principal comes from the presented token and is never taken
 * from the body. A credential surface that accepts a subject in the request is a surface where one
 * person registers a key against another person's account.
 */
export async function enrollmentController(fastify: FastifyInstance) {
  const base = '/realms/:realm/credentials';

  function fail(reply: never | { status: (code: number) => { send: (body: unknown) => unknown } }, status: number, error: string, description?: string) {
    return reply.status(status).send({ error, ...(description ? { error_description: description } : {}) });
  }

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  /**
   * `alg` is accepted alongside `algorithm` because `alg` is what JOSE calls this field, and a device
   * that already speaks JOSE should not have to learn a second spelling. Unknown members are ignored
   * rather than refused, so an authenticator may send its own metadata without being rejected for it.
   */
  const registrationBody = {
    type: 'object',
    required: ['challenge', 'publicKeyPem', 'signature'],
    additionalProperties: true,
    properties: {
      challenge: { type: 'string', description: 'The challenge this endpoint issued.' },
      publicKeyPem: { type: 'string', description: 'The PUBLIC half. The private half never leaves the device.' },
      algorithm: { type: 'string', enum: ['RS256', 'ES256'] },
      alg: { type: 'string', enum: ['RS256', 'ES256'], description: 'The JOSE spelling of algorithm.' },
      signature: { type: 'string', description: 'base64url signature over the challenge, proving possession.' },
      credentialId: { type: 'string' },
      label: { type: 'string', description: 'What the person calls this device.' },
    },
  } as const;

  /** One shape from either spelling, so nothing below this line has to know both. */
  function registration(body: unknown): RegisterInput {
    const presented = (body ?? {}) as Record<string, unknown> & { authenticatorMetadata?: { deviceName?: string } };
    return {
      challenge: String(presented.challenge ?? ''),
      publicKeyPem: String(presented.publicKeyPem ?? ''),
      algorithm: (presented.algorithm ?? presented.alg) as RegisterInput['algorithm'],
      signature: String(presented.signature ?? ''),
      ...(presented.credentialId ? { credentialId: String(presented.credentialId) } : {}),
      ...(presented.label ? { label: String(presented.label) }
        : presented.authenticatorMetadata?.deviceName ? { label: presented.authenticatorMetadata.deviceName } : {}),
    };
  }

  const credentialView = {
    type: 'object',
    additionalProperties: false,
    required: ['credentialId', 'algorithm', 'status', 'createdAt'],
    properties: {
      credentialId: { type: 'string' },
      algorithm: { type: 'string' },
      label: { type: 'string' },
      status: { type: 'string' },
      createdAt: { type: 'string' },
      lastUsedAt: { type: 'string' },
    },
    examples: [{
      credentialId: 'c9f2…',
      algorithm: 'ES256',
      label: 'Phone',
      status: 'active',
      createdAt: '2026-08-29T09:12:04.000Z',
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  fastify.post(`${base}/challenge`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'issueRegistrationChallenge',
      tags: ['authentication'],
      summary: 'Start registering an authenticator',
      description:
        'No applicable standard for the transport; the ceremony follows the WebAuthn registration '
        + 'model. The challenge is stateless and keyed, so there is no ceremony record to store, to '
        + 'expire or to clean up.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The challenge to sign.',
          type: 'object',
          additionalProperties: false,
          required: ['challenge', 'expiresIn'],
          properties: { challenge: { type: 'string' }, expiresIn: { type: 'integer' } },
          examples: [{ challenge: 'eyJ…', expiresIn: 300 }],
        },
        401: { $ref: 'OAuthError#', description: 'No valid access token.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    return reply.send(new EnrollmentService(fastify.db).issueChallenge(principal.subjectId));
  });

  fastify.post(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'registerCredential',
      tags: ['authentication'],
      summary: 'Register an authenticator',
      description:
        'No applicable standard for the transport; the ceremony follows the WebAuthn registration '
        + 'model. Only the public half is stored, so a full dump of the credential store lets nobody '
        + 'authenticate as anybody.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: registrationBody,
      response: {
        200: { ...credentialView, description: 'The registered credential.' },
        400: { $ref: 'OAuthError#', description: 'The challenge or the algorithm is invalid.' },
        401: { $ref: 'OAuthError#', description: 'The proof did not verify.' },
        409: { $ref: 'OAuthError#', description: 'That credential id is already registered.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    const result = await new EnrollmentService(fastify.db)
      .register(realm, principal.subjectId, registration(request.body));
    if (isEnrollmentFailure(result)) return fail(reply as never, result.status, result.error, result.description);
    return reply.send(result);
  });

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listCredentials',
      tags: ['authentication'],
      summary: 'The authenticators the caller has registered',
      description:
        'No applicable standard. Scoped to the caller, so this cannot be used to enumerate anyone '
        + "else's devices.",
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: "The caller's registered authenticators.",
          type: 'object',
          additionalProperties: false,
          required: ['credentials'],
          properties: { credentials: { type: 'array', items: credentialView } },
          examples: [{
            credentials: [{
              credentialId: 'c9f2…',
              algorithm: 'ES256',
              label: 'Phone',
              status: 'active',
              createdAt: '2026-08-29T09:12:04.000Z',
            }],
          }],
        },
        401: { $ref: 'OAuthError#', description: 'No valid access token.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    return reply.send({ credentials: await new EnrollmentService(fastify.db).list(principal.subjectId) });
  });

  fastify.delete(`${base}/:credentialId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'revokeCredential',
      tags: ['authentication'],
      summary: 'Retire an authenticator',
      description:
        'No applicable standard. Revoked rather than deleted, so a later question about what could '
        + 'sign at a given moment still has an answer.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'credentialId'],
        properties: { realm: { type: 'string' }, credentialId: { type: 'string' } },
      },
      response: {
        // Answered with the retired credential rather than an empty 204, so the caller can show what
        // it just retired without a second read, and the operation documents an example like the rest.
        200: { ...credentialView, description: 'Retired.' },
        401: { $ref: 'OAuthError#', description: 'No valid access token.' },
        404: { $ref: 'OAuthError#', description: 'No such credential for this caller.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    const { realm: realmName, credentialId } = request.params as { realm: string; credentialId: string };
    const realm = await realmOf(realmName);
    if (!realm) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    const service = new EnrollmentService(fastify.db);
    const result = await service.revoke(realm, principal.subjectId, credentialId);
    if (isEnrollmentFailure(result)) return fail(reply as never, result.status, result.error, result.description);

    const retired = (await service.list(principal.subjectId)).find((c) => c.credentialId === credentialId);
    return reply.send(retired);
  });

  fastify.post(`${base}/:credentialId/rotate`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'rotateCredential',
      tags: ['authentication'],
      summary: 'Replace an authenticator',
      description:
        'No applicable standard. The replacement is registered before the old one is retired, so a '
        + 'failed rotation never leaves the person with no way to authenticate.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'credentialId'],
        properties: { realm: { type: 'string' }, credentialId: { type: 'string' } },
      },
      body: registrationBody,
      response: {
        200: { ...credentialView, description: 'The replacement credential.' },
        400: { $ref: 'OAuthError#', description: 'The challenge or the algorithm is invalid.' },
        401: { $ref: 'OAuthError#', description: 'The proof did not verify.' },
        404: { $ref: 'OAuthError#', description: 'No such credential for this caller.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    const { realm: realmName, credentialId } = request.params as { realm: string; credentialId: string };
    const realm = await realmOf(realmName);
    if (!realm) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    const result = await new EnrollmentService(fastify.db)
      .rotate(realm, principal.subjectId, credentialId, registration(request.body));
    if (isEnrollmentFailure(result)) return fail(reply as never, result.status, result.error, result.description);
    return reply.send(result);
  });
}
