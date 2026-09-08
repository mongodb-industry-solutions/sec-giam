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
      { projection: { _id: 0, credentialId: 1 } },
    );

    if (existing) {
      await credentials.updateOne(
        { credentialId: existing.credentialId },
        { $set: { hash: issued?.hash as string, 'meta.lastModified': new Date().toISOString() } },
      );
    } else {
      await credentials.insertOne({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        credentialId: `cred-${randomUUID()}`,
        subjectId: id,
        type: 'password',
        hash: issued?.hash as string,
        status: 'active',
        assurance: { level: 'aal1', method: 'password', verifiedAt: new Date().toISOString() },
        meta: newMeta('Credential'),
      } as CredentialRecord);
    }

    // The value itself never appears here, only that a change happened and who made it.
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'identity.password_reset',
      outcome: 'success',
      // Absent for the break-glass operator credential, which is nobody in particular.
      ...(request.authorityCaller?.subjectId ? { subjectId: request.authorityCaller.subjectId } : {}),
      target: { type: 'principal', ref: id },
    });

    return reply.send({ reset: true });
  });
}
