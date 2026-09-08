import { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { credentialStores } from '../../../shared/ports';
import { checkPassword, describeRefusals, passwordPolicyOf } from '../../realm/models/domain.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requireAuthority } from '../../../vendors/middleware/authorityAuth';
import { PRINCIPAL_COLLECTION, CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { PrincipalRecord } from '../models/principal.model';
import { CredentialRecord } from '../models/credential.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';
import { DirectoryService } from '../services/directory.service';
import { EnrollmentService, isEnrollmentFailure } from '../../authentication/services/enrollment.service';
import { recordConfigurationChange } from '../../audit/services/configurationChange';

/**
 * An administrator setting somebody else's password.
 *
 * Deliberately not part of SCIM: `scim.controller.ts` keeps to the standard's own vocabulary, and a
 * credential reset is not one of its attributes. This is the LeafyPay-era "forced password reset"
 * capability, rebuilt against the current credential model instead of a bespoke user table.
 *
 * The new password replaces the existing hash in place. Whether a principal must change it again at
 * next sign-in (`mustChangePassword`) is explicitly OUT of scope here: that is a model change (a new
 * field on `credential`, checked by the login path) and is deferred, not silently dropped. See
 * `.agents/specs/dev.v43.giam-admin.md` P4.
 */
export async function credentialAdminController(fastify: FastifyInstance) {
  fastify.post('/realms/:realm/identities/:id/credentials/password', {
    preHandler: requireAuthority('identities', 'manage'),
    schema: {
      operationId: 'resetPassword',
      tags: ['directory'],
      summary: 'Set a new password for a principal',
      description:
        'No applicable standard; administrative credential reset. Checked against the same policy '
        + 'self-registration enforces, on the same local domain, so an administrator cannot set a '
        + 'password the person themselves would have been refused. The new password is never '
        + 'returned or logged.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id'],
        properties: { realm: { type: 'string' }, id: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['password'],
        additionalProperties: false,
        properties: { password: { type: 'string', minLength: 8 } },
      },
      response: {
        200: {
          type: 'object',
          additionalProperties: false,
          required: ['reset'],
          properties: { reset: { type: 'boolean' } },
          examples: [{ reset: true }],
        },
        400: { $ref: 'Problem#', description: 'Does not meet the password policy.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits administering the directory.' },
        404: { $ref: 'Problem#', description: 'No such realm or principal.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id } = request.params as { realm: string; id: string };
    const { password } = request.body as { password: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const principal = await fastify.db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION)
      .findOne({ realmId: realm.realmId, subjectId: id }, { projection: { _id: 0, subjectId: 1 } });
    if (!principal) return reply.status(404).send(problem(404, 'No such principal'));

    const localDomain = await new RealmService(fastify.db).localDomain(realm.realmId);
    const broken = checkPassword(passwordPolicyOf(localDomain ?? { protocol: 'internal' }), password);
    if (broken.length > 0) {
      return reply.status(400).send(problem(
        400,
        'Password does not meet the policy',
        `This realm requires ${describeRefusals(broken)}.`,
      ));
    }

    const store = credentialStores.resolve('bcrypt-password');
    const issued = await store.issue(id, password);
    const credentials = fastify.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);

    const existing = await credentials.findOne(
      { realmId: realm.realmId, subjectId: id, type: 'password', status: 'active' },
      { projection: { _id: 0 } },
    );
    const newCredentialId = `cred-${randomUUID()}`;

    if (existing) {
      await credentials.updateOne(
        { credentialId: existing.credentialId },
        { $set: { hash: issued?.hash as string, 'meta.lastModified': new Date().toISOString() } },
      );
    } else {
      await credentials.insertOne({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        credentialId: newCredentialId,
        subjectId: id,
        type: 'password',
        hash: issued?.hash as string,
        status: 'active',
        assurance: { level: 'aal1', method: 'password', verifiedAt: new Date().toISOString() },
        createdAt: new Date().toISOString(),
        meta: newMeta('Credential'),
      } as CredentialRecord);
    }

    const after = await credentials.findOne(
      { realmId: realm.realmId, subjectId: id, type: 'password', status: 'active' },
      { projection: { _id: 0 } },
    ) as unknown as Record<string, unknown>;

    /**
     * `hash` is named in `ignore` rather than trusted to be absent: PCI DSS 10.2.1.x asks for
     * changes to authentication credentials to be recorded, not the credential material itself, and
     * the two records passed here are the real before/after documents, hash included, precisely so a
     * copy-paste elsewhere in this diff cannot forget to strip it.
     *
     * `recordConfigurationChange` requires a real actor by design ("an act nobody can attribute
     * later should not be possible"), so the break-glass operator credential, which is nobody in
     * particular, falls back to the plain event the rest of this authority already uses for it
     * rather than fabricating a subject.
     */
    if (request.authorityCaller?.subjectId) {
      await recordConfigurationChange(fastify.db, {
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        what: 'credential',
        ref: existing?.credentialId ?? newCredentialId,
        operation: existing ? 'reset' : 'created',
        actorSubjectId: request.authorityCaller.subjectId,
        before: existing ? (existing as unknown as Record<string, unknown>) : null,
        after,
        ignore: ['meta', '_id', 'hash'],
      });
    } else {
      void new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'lifecycle',
        action: 'identity.password_reset',
        outcome: 'success',
        target: { type: 'principal', ref: id },
      });
    }

    return reply.send({ reset: true });
  });

  const credentialView = {
    type: 'object',
    additionalProperties: false,
    required: ['credentialId', 'type', 'status', 'createdAt'],
    properties: {
      credentialId: { type: 'string' },
      type: {
        type: 'string',
        enum: ['password', 'public_key', 'client_secret', 'totp', 'recovery_code', 'api_key', 'oauth_client'],
      },
      label: { type: 'string' },
      clientId: { type: 'string', description: 'The wire identifier, for an `oauth_client` or `api_key`.' },
      clientName: { type: 'string', description: 'For `oauth_client`: the name it registered under.' },
      status: { type: 'string', enum: ['active', 'suspended', 'revoked'] },
      createdAt: { type: 'string' },
      lastUsedAt: { type: 'string' },
      expiresAt: { type: 'string' },
    },
    examples: [{
      credentialId: 'cred-4c1f',
      type: 'public_key',
      label: 'Phone',
      status: 'active',
      createdAt: '2026-08-29T09:12:04.000Z',
    }],
  } as const;

  function redact(credential: CredentialRecord) {
    return {
      credentialId: credential.credentialId,
      type: credential.type,
      ...(credential.label ? { label: credential.label } : {}),
      ...(credential.clientId ? { clientId: credential.clientId } : {}),
      ...(credential.metadata?.clientName ? { clientName: credential.metadata.clientName } : {}),
      status: credential.status,
      // Falls back to the envelope's own `created`: every insert sets that one, even the couple of
      // call sites that (until now) forgot the credential's own `createdAt`.
      createdAt: credential.createdAt ?? credential.meta.created,
      ...(credential.lastUsedAt ? { lastUsedAt: credential.lastUsedAt } : {}),
      ...(credential.expiresAt ? { expiresAt: credential.expiresAt } : {}),
    };
  }

  /**
   * Every credential a principal holds, one type discriminated collection read whole.
   *
   * Not a replacement for the application registry or the authenticator screen: those stay the place
   * to REGISTER one. This is the oversight view a per-type screen cannot give on its own, which is
   * "everything this principal could currently authenticate with, in one place".
   */
  fastify.get('/realms/:realm/identities/:id/credentials', {
    preHandler: requireAuthority('identities', 'view'),
    schema: {
      operationId: 'listPrincipalCredentials',
      tags: ['directory'],
      summary: 'Every credential a principal holds',
      description:
        'No applicable standard. One view across every credential type this authority recognises '
        + '(password, authenticator, OAuth application, and any other), because they are all the same '
        + 'kind of record discriminated by type rather than kept in separate registries. Secret '
        + 'material (a hash, a public key) is never returned, only what identifies and describes each.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id'],
        properties: { realm: { type: 'string' }, id: { type: 'string' } },
      },
      response: {
        200: {
          description: 'The credentials held.',
          type: 'object',
          additionalProperties: false,
          required: ['credentials'],
          properties: { credentials: { type: 'array', items: credentialView } },
          examples: [{ credentials: [credentialView.examples[0]] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits administering the directory.' },
        404: { $ref: 'Problem#', description: 'No such realm or principal.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id } = request.params as { realm: string; id: string };
    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const principal = await fastify.db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION)
      .findOne({ realmId: realm.realmId, subjectId: id }, { projection: { _id: 0, subjectId: 1 } });
    if (!principal) return reply.status(404).send(problem(404, 'No such principal'));

    const credentials = await new DirectoryService(fastify.db).allCredentialsFor(realm.realmId, id);
    return reply.send({ credentials: credentials.map(redact) });
  });

  /**
   * Retiring an authenticator on somebody else's behalf: a lost or compromised device, when the
   * owner cannot retire it themselves.
   *
   * `DELETE` on the credential itself, matching the self-service route's own verb
   * (`DELETE /credentials/:credentialId` in `enrollment.controller.ts`) exactly, rather than a `POST
   * .../revoke` action route: the same operation deserves the same shape whether it is done to your
   * own authenticator or, here, to somebody else's. It also keeps this path out of
   * `isOAuthSurface`'s `revoke` pattern, which exists for RFC 7009 token revocation and would
   * otherwise mislabel every error on this route as an OAuth error the caller never asked for.
   *
   * Scoped to `public_key` on purpose. An `oauth_client` is withdrawn from the application registry
   * it was registered in (`DELETE /clients/:clientId`), which already does the extra work a client
   * withdrawal needs (dropping the secret hash, ending sessions); reimplementing that here would be
   * the same operation with two code paths to keep in sync. A `password` is not revoked at all, it
   * is REPLACED, which is what the reset route above is for. Every other type has no route of its
   * own yet, and refusing them here rather than guessing is more honest than a silent no-op.
   */
  fastify.delete('/realms/:realm/identities/:id/credentials/:credentialId', {
    preHandler: requireAuthority('identities', 'manage'),
    schema: {
      operationId: 'revokePrincipalCredential',
      tags: ['directory'],
      summary: 'Retire an authenticator on a principal\'s behalf',
      description:
        'No applicable standard. For an authenticator (`public_key`) the owner has lost or no longer '
        + 'controls. An OAuth application is withdrawn from the application registry instead, and a '
        + 'password is replaced by a reset rather than revoked; both are refused here, naming the '
        + 'right action, rather than silently doing something narrower than what was asked.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'id', 'credentialId'],
        properties: { realm: { type: 'string' }, id: { type: 'string' }, credentialId: { type: 'string' } },
      },
      response: {
        200: { ...credentialView, description: 'Retired.' },
        400: { $ref: 'Problem#', description: 'Not an authenticator: withdraw the application, or reset the password, instead.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits administering the directory.' },
        404: { $ref: 'Problem#', description: 'No such realm, principal or credential.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, id, credentialId } = request.params as { realm: string; id: string; credentialId: string };
    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const credentials = fastify.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
    const existing = await credentials.findOne(
      { realmId: realm.realmId, subjectId: id, credentialId },
      { projection: { _id: 0 } },
    );
    if (!existing) return reply.status(404).send(problem(404, 'No such credential for this principal'));
    if (existing.type !== 'public_key') {
      const guidance = existing.type === 'oauth_client'
        ? 'Withdraw this OAuth application from the application registry instead.'
        : existing.type === 'password'
          ? 'A password is replaced by a reset, not revoked.'
          : `Credentials of type "${existing.type}" have no retirement route yet.`;
      return reply.status(400).send(problem(400, 'Not an authenticator', guidance));
    }

    const outcome = await new EnrollmentService(fastify.db)
      .revoke(realm, id, credentialId, { subjectId: request.authorityCaller?.subjectId });
    if (isEnrollmentFailure(outcome)) {
      // `revoke` only ever refuses with 404 (no such credential), reached here in the unlikely race
      // where it was retired between the lookup above and this call.
      return reply.status(outcome.status as 404).send(problem(outcome.status, 'Could not retire that authenticator', outcome.description));
    }

    const retired = await credentials.findOne(
      { realmId: realm.realmId, subjectId: id, credentialId },
      { projection: { _id: 0 } },
    );
    return reply.send(redact(retired as CredentialRecord));
  });
}
