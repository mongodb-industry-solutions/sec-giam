import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { EnrollmentService, isEnrollmentFailure, RegisterInput } from '../services/enrollment.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { credentialStores } from '../../../shared/ports';
import { checkPassword, describeRefusals, passwordPolicyOf } from '../../realm/models/domain.model';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { CredentialRecord } from '../../directory/models/credential.model';
import { DirectoryService } from '../../directory/services/directory.service';
import { problem } from '../../../shared/models/problem';
import { recordConfigurationChange } from '../../audit/services/configurationChange';

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
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
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
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
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
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    return reply.send({ credentials: await new EnrollmentService(fastify.db).list(principal.subjectId) });
  });

  /**
   * The rules a new password must satisfy, before one is submitted.
   *
   * Published so a form can tell somebody what is required WHILE they type rather than refusing them
   * afterwards. The policy is not a secret: the sign-in and registration paths already enforce it,
   * and a person cannot satisfy a rule nobody told them about.
   *
   * Answers for the CALLER's realm and carries no permission gate beyond holding a token, the same
   * reasoning `/me/permissions` follows: this is a property of the realm the caller is already in,
   * and reading it reveals nothing about anybody else.
   *
   * This is the source the console renders, so the checklist and the refusal come from one policy
   * rather than from a constant somebody copied into a form.
   */
  fastify.get(`${base}/password/policy`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'passwordPolicy',
      tags: ['authentication'],
      summary: 'The rules a new password must satisfy',
      description:
        'No applicable standard; PCI DSS 8.3.6-adjacent, which expects the password requirements to '
        + 'be communicated rather than discovered by being refused. The same policy '
        + '`POST /credentials/password` and self-registration enforce, resolved from the directory this '
        + 'realm owns. Null when the realm authenticates through an upstream that sets its own.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The policy in force, or nulls when this realm sets none.',
          type: 'object',
          additionalProperties: false,
          required: ['policy'],
          properties: {
            policy: {
              type: ['object', 'null'],
              additionalProperties: false,
              required: ['minLength', 'requireUppercase', 'requireNumber', 'requireSymbol', 'historyDepth'],
              properties: {
                minLength: { type: 'integer' },
                requireUppercase: { type: 'boolean' },
                requireNumber: { type: 'boolean' },
                requireSymbol: {
                  type: 'boolean',
                  description: 'Anything that is not a letter, a digit or whitespace. Deliberately broad.',
                },
                historyDepth: {
                  type: 'integer',
                  description: 'How many previous credentials may not be reused. Zero means no history is kept.',
                },
              },
            },
          },
          examples: [{ policy: { minLength: 8, requireUppercase: false, requireNumber: false, requireSymbol: false, historyDepth: 0 } }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const localDomain = await new RealmService(fastify.db).localDomain(realm.realmId);
    return reply.send({ policy: passwordPolicyOf(localDomain ?? { protocol: 'internal' }) });
  });

  /**
   * Changing one's own password.
   *
   * The self-service counterpart of the administrative reset in credentialAdmin.controller.ts: same
   * policy, same store, same audit trail, but proof of the CURRENT password stands in for the
   * authority permission an administrator would otherwise need. A caller who cannot present the
   * password they already hold has proven nothing; one who can has proven exactly what the login
   * path itself would have accepted, which is what makes this safe to expose with no role at all.
   *
   * Never creates a password credential that did not already exist: that is what the login roster
   * and the enrollment ceremony are for, and a self-service path that could conjure a fresh
   * authentication factor would be a second, unaudited way to enroll one.
   *
   * Kept on the Problem shape the administrative reset uses, not the OAuthError shape the WebAuthn
   * routes above use: this is the same operation addressed at a different caller, and the two
   * should read as one capability with two doors rather than as two unrelated ones that share a
   * policy by coincidence.
   */
  fastify.post(`${base}/password`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'changePassword',
      tags: ['authentication'],
      summary: 'Change your own password',
      description:
        'No applicable standard; self-service counterpart of the administrative reset. Requires the '
        + 'current password, checked against the same policy self-registration enforces. Neither '
        + 'password is ever returned or logged.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      body: {
        type: 'object',
        required: ['currentPassword', 'newPassword', 'newPasswordConfirmation'],
        additionalProperties: false,
        properties: {
          currentPassword: { type: 'string', description: 'What signs the caller in today.' },
          newPassword: { type: 'string', minLength: 8 },
          newPasswordConfirmation: {
            type: 'string',
            description: 'Repeated so a typo is caught here rather than at the next sign-in.',
          },
        },
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['changed'],
          properties: { changed: { type: 'boolean' } },
          examples: [{ changed: true }],
        },
        400: {
          $ref: 'Problem#',
          description: 'The new password fails the policy, repeats the current one, or does not match its confirmation.',
        },
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
        403: { $ref: 'Problem#', description: 'The current password does not match.' },
        404: { $ref: 'Problem#', description: 'No password credential to change; this principal signs in another way.' },
      },
    },
  }, async (request, reply) => {
    const principal = request.principal!;
    const { realm: realmName } = request.params as { realm: string };
    const { currentPassword, newPassword, newPasswordConfirmation } = request.body as {
      currentPassword: string;
      newPassword: string;
      newPasswordConfirmation: string;
    };

    if (newPassword !== newPasswordConfirmation) {
      return reply.status(400).send(
        problem(400, 'Passwords do not match', 'The new password and its confirmation must be identical.'),
      );
    }
    if (newPassword === currentPassword) {
      return reply.status(400).send(
        problem(400, 'Password unchanged', 'The new password must differ from the current one.'),
      );
    }

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const held = await new DirectoryService(fastify.db).credentialsFor(principal.subjectId, 'password');
    if (held.length === 0) {
      return reply.status(404).send(
        problem(404, 'No password to change', 'This principal signs in another way.'),
      );
    }

    // Same loop the login path itself runs (authenticationMethods.ts), because a person may hold
    // more than one active password credential and any one of them proving current is what a
    // sign-in would have accepted too.
    const store = credentialStores.resolve('bcrypt-password');
    let matched: CredentialRecord | null = null;
    for (const credential of held) {
      if (await store.verify(credential.credentialId, currentPassword)) { matched = credential; break; }
    }
    if (!matched) {
      return reply.status(403).send(
        problem(403, 'Current password does not match', 'Sign in again if you no longer remember it.'),
      );
    }

    const localDomain = await new RealmService(fastify.db).localDomain(realm.realmId);
    const broken = checkPassword(passwordPolicyOf(localDomain ?? { protocol: 'internal' }), newPassword);
    if (broken.length > 0) {
      return reply.status(400).send(problem(
        400,
        'Password does not meet the policy',
        `This realm requires ${describeRefusals(broken)}.`,
      ));
    }

    const issued = await store.issue(principal.subjectId, newPassword);
    const credentials = fastify.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
    await credentials.updateOne(
      { credentialId: matched.credentialId },
      { $set: { hash: issued?.hash as string, 'meta.lastModified': new Date().toISOString() } },
    );

    const after = await credentials.findOne(
      { credentialId: matched.credentialId },
      { projection: { _id: 0 } },
    ) as unknown as Record<string, unknown>;

    // The actor and the target are the same person here, unlike the administrative reset, and that
    // is recorded rather than special-cased: the trail should say who changed the credential exactly
    // as plainly when the answer is themselves as when it is somebody else.
    await recordConfigurationChange(fastify.db, {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      what: 'credential',
      ref: matched.credentialId,
      operation: 'reset',
      actorSubjectId: principal.subjectId,
      before: matched as unknown as Record<string, unknown>,
      after,
      ignore: ['meta', '_id', 'hash'],
    });

    return reply.send({ changed: true });
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
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
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
        401: { $ref: 'Problem#', description: 'No valid access token for this realm.' },
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
