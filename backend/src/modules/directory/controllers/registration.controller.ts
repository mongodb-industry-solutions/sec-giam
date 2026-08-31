import { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../services/directory.service';
import { IDENTITY_COLLECTION, CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { IdentityRecord } from '../models/identity.model';
import { CredentialRecord } from '../models/credential.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { credentialStores } from '../../../shared/ports';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Self-service registration, where a realm allows it.
 *
 * Whether it is allowed, and whether a new principal is active immediately or waits for approval,
 * are properties of the REALM rather than of this code. That is what makes the same build correct
 * for a public sign-up and for an organisation where every account is provisioned: what differs is
 * configuration, not a branch asking which deployment this is.
 */
export async function registrationController(fastify: FastifyInstance) {
  fastify.post('/realms/:realm/register', {
    schema: {
      operationId: 'registerIdentity',
      tags: ['directory'],
      summary: 'Create a principal, where the realm permits it',
      description:
        'No applicable standard; SCIM covers administrative provisioning, not self-service sign-up. '
        + 'Public by nature: somebody who has no account cannot present one to make one. Whether the '
        + 'result is active or awaiting approval is the realm\'s policy, not this route\'s.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['userName', 'password'],
        additionalProperties: false,
        properties: {
          userName: { type: 'string', description: 'What this principal signs in as.' },
          password: { type: 'string', minLength: 8 },
          email: { type: 'string' },
          formattedName: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'The principal, and whether it may sign in yet.',
          type: 'object',
          additionalProperties: false,
          required: ['subjectId', 'status'],
          properties: {
            subjectId: { type: 'string' },
            userName: { type: 'string' },
            status: { type: 'string', examples: ['active'] },
          },
          examples: [{ subjectId: 'sub-9f21', userName: 'ada', status: 'active' }],
        },
        400: { $ref: 'Problem#', description: 'The request is incomplete.' },
        403: { $ref: 'Problem#', description: 'This realm does not offer self-service registration.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That user name is taken.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as { userName: string; password: string; email?: string; formattedName?: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm || !realm.enabled) return reply.status(404).send(problem(404, 'Unknown realm'));
    if (!realm.registration.selfServiceEnabled) {
      return reply.status(403).send(problem(403, 'Registration is closed', 'This realm does not offer self-service registration.'));
    }

    const directory = new DirectoryService(fastify.db);
    const userName = body.userName.trim();
    // A taken name is reported as taken. It is a disclosure, and an unavoidable one: a sign-up form
    // that accepts a duplicate and fails later is worse for everybody including the person whose
    // name it is.
    if (await directory.findByLogin(realm.realmId, userName)) {
      return reply.status(409).send(problem(409, 'That user name is taken'));
    }

    const subjectId = `sub-${randomUUID()}`;
    const now = new Date().toISOString();
    // Approval is the realm's decision. A principal awaiting it exists and cannot authenticate,
    // rather than not existing, so the person can be told where their request stands.
    const lifecycleState = realm.registration.autoApprove ? 'active' : 'pending';

    await fastify.db.collection<IdentityRecord>(IDENTITY_COLLECTION).insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      subjectId,
      userName,
      ...(body.email ? { primaryEmail: body.email.toLowerCase() } : {}),
      ...(body.formattedName ? { name: { formatted: body.formattedName } } : {}),
      kind: 'human',
      // Two fields rather than one because they answer different questions: whether this principal is
      // usable at all, and where it stands in its lifecycle. A realm that reviews sign-ups produces a
      // principal that EXISTS and cannot authenticate, so the person can be told where they stand.
      active: lifecycleState === 'active',
      lifecycleState,
      sessionEpoch: 0,
      meta: newMeta('Identity'),
    } as IdentityRecord);

    const store = credentialStores.resolve('bcrypt-password');
    const issued = await store.issue(subjectId, body.password);
    await fastify.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION).insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      credentialId: `cred-${randomUUID()}`,
      subjectId,
      type: 'password',
      secretHash: issued?.secretHash as string,
      status: 'active',
      assurance: { level: 'aal1', method: 'password', verifiedAt: now },
      meta: newMeta('Credential'),
    } as CredentialRecord);

    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      action: 'identity.registered',
      outcome: 'success',
      subjectId,
      detail: { selfService: true, lifecycleState },
    });

    return reply.send({ subjectId, userName, status: lifecycleState });
  });
}
