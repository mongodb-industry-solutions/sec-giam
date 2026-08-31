import { FastifyInstance } from 'fastify';
import { randomUUID } from 'crypto';
import { RealmService } from '../services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { SessionService } from '../../authentication/services/session.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { identityProviders } from '../../../shared/ports';
import { bindIdentityProviders } from '../services/oidcProvider';
import { IDENTITY_COLLECTION, IDENTITY_PROVIDER_COLLECTION, ROLE_COLLECTION, ROLE_ASSIGNMENT_COLLECTION } from '../../../shared/models/collections';
import { IdentityRecord } from '../../directory/models/identity.model';
import { IdentityProviderRecord } from '../models/identityProvider.model';
import { RoleAssignmentRecord, RoleRecord } from '../../authorization/models/authorization.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Signing in through somebody else's identity provider.
 *
 * The upstream provider says who the person is. It does NOT say what they may do: the claim mapping
 * on the provider record turns upstream group names into local roles, and the local role is what any
 * decision is made against. Letting an upstream directory grant permissions here directly would mean
 * whoever administers it can grant themselves anything in this system.
 *
 * A principal arriving this way is linked by its upstream identifier rather than by email. An email
 * can be reassigned inside an organisation, and matching on one is how a new joiner inherits a
 * previous holder's account.
 */
export async function federationController(fastify: FastifyInstance) {
  // The adapter reads provider records, so it is bound to this database rather than given one on
  // every call: the port stays free of any storage vocabulary.
  bindIdentityProviders(fastify.db);

  const realmService = () => new RealmService(fastify.db);

  fastify.get('/realms/:realm/federation/:provider/start', {
    schema: {
      operationId: 'startFederation',
      tags: ['authentication'],
      summary: 'Begin signing in through an upstream provider',
      description:
        'Standard-defined: OpenID Connect Core 1.0 authentication request, made by this authority as '
        + 'a relying party of the upstream provider. Public, because it is the first step of a '
        + 'sign-in and the person has nothing to present yet.',
      security: [],
      params: {
        type: 'object',
        required: ['realm', 'provider'],
        properties: { realm: { type: 'string' }, provider: { type: 'string', examples: ['entra'] } },
      },
      response: {
        200: {
          description: 'Where to send the browser, and the state to expect back.',
          type: 'object',
          additionalProperties: false,
          required: ['authorizationUrl', 'state'],
          properties: { authorizationUrl: { type: 'string' }, state: { type: 'string' } },
          examples: [{ authorizationUrl: 'https://login.example/authorize?…', state: 'a1b2c3' }],
        },
        404: { $ref: 'Problem#', description: 'No such realm or provider.' },
        503: { $ref: 'Problem#', description: 'The provider is configured but not reachable.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, provider: providerName } = request.params as { realm: string; provider: string };
    const realm = await realmService().byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const provider = await fastify.db.collection<IdentityProviderRecord>(IDENTITY_PROVIDER_COLLECTION)
      .findOne({ realmId: realm.realmId, name: providerName, enabled: true }, { projection: { _id: 0 } });
    if (!provider) return reply.status(404).send(problem(404, 'Unknown provider'));

    try {
      const adapter = identityProviders.resolve(provider.adapter);
      const state = randomUUID();
      const authorizationUrl = await adapter.authorizationUrl(provider.providerId, state);
      if (!authorizationUrl) return reply.status(404).send(problem(404, 'That provider has no redirect step'));
      return reply.send({ authorizationUrl, state });
    } catch (cause) {
      // Reported as an outage rather than a refusal: the person did nothing wrong, and an operator
      // reading "unauthorized" would go looking in the wrong place entirely.
      return reply.status(503).send(problem(503, 'The provider is unavailable', (cause as Error).message));
    }
  });

  fastify.post('/realms/:realm/federation/:provider/callback', {
    schema: {
      operationId: 'completeFederation',
      tags: ['authentication'],
      summary: 'Complete a sign-in through an upstream provider',
      description:
        'Standard-defined: OpenID Connect Core 1.0 code exchange, with the upstream id token verified '
        + 'against the provider\'s published keys before any claim in it is believed. Public for the '
        + 'same reason the sign-in route is: the code IS the credential being presented.',
      security: [],
      params: {
        type: 'object',
        required: ['realm', 'provider'],
        properties: { realm: { type: 'string' }, provider: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['code', 'state'],
        additionalProperties: false,
        properties: {
          code: { type: 'string' },
          state: { type: 'string', description: 'The value this authority issued when the flow started.' },
        },
      },
      response: {
        200: {
          description: 'The local principal, and the session established for it.',
          type: 'object',
          additionalProperties: false,
          required: ['subjectId', 'sessionId'],
          properties: {
            subjectId: { type: 'string' },
            sessionId: { type: 'string' },
            userName: { type: 'string' },
            provisioned: { type: 'boolean', description: 'True when this sign-in created the principal.' },
          },
          examples: [{ subjectId: 'sub-9f21', sessionId: 'ses-4c1f', userName: 'ada', provisioned: false }],
        },
        401: { $ref: 'Problem#', description: 'The upstream response did not verify.' },
        404: { $ref: 'Problem#', description: 'No such realm or provider.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, provider: providerName } = request.params as { realm: string; provider: string };
    const { code, state } = request.body as { code: string; state: string };

    const realm = await realmService().byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const provider = await fastify.db.collection<IdentityProviderRecord>(IDENTITY_PROVIDER_COLLECTION)
      .findOne({ realmId: realm.realmId, name: providerName, enabled: true }, { projection: { _id: 0 } });
    if (!provider) return reply.status(404).send(problem(404, 'Unknown provider'));

    const audit = new SecurityEventService(fastify.db);
    let claims: Record<string, unknown>;
    try {
      claims = await identityProviders.resolve(provider.adapter).exchange(provider.providerId, { code, state });
    } catch (cause) {
      void audit.record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authentication',
        action: 'authentication.federated',
        outcome: 'failure',
        cause: (cause as Error).message,
        detail: { provider: provider.name },
      });
      // One message, as everywhere else a credential is judged. Which check failed is not something
      // the person can act on, and saying so would describe this authority's verification to whoever
      // is probing it.
      return reply.status(401).send(problem(401, 'That sign-in could not be completed'));
    }

    const externalId = String(claims.sub ?? '');
    const identities = fastify.db.collection<IdentityRecord>(IDENTITY_COLLECTION);
    // Linked by upstream identifier, never by email: an address can be reassigned inside an
    // organisation, and matching on one is how a new joiner inherits somebody else's account.
    let identity: IdentityRecord | null = await identities.findOne(
      { realmId: realm.realmId, providerId: provider.providerId, externalId },
      { projection: { _id: 0 } },
    );

    const provisioned = !identity;
    if (!identity) {
      const now = new Date().toISOString();
      const record = {
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        subjectId: `sub-${randomUUID()}`,
        userName: String(claims.preferred_username ?? claims.email ?? externalId),
        kind: 'human',
        ...(claims.email ? { primaryEmail: String(claims.email).toLowerCase() } : {}),
        ...(claims.name ? { name: { formatted: String(claims.name) } } : {}),
        active: true,
        lifecycleState: 'active',
        sessionEpoch: 0,
        externalId,
        providerId: provider.providerId,
        meta: newMeta('Identity'),
      } as unknown as IdentityRecord;
      await identities.insertOne(record);
      identity = record;
    }

    // The upstream says who; the mapping says what. A provider that could grant permissions directly
    // would let whoever administers it grant themselves anything here.
    await applyRoleMapping(realm.realmId, realm.tenantId, identity.subjectId, provider, claims);

    const session = await new SessionService(fastify.db).start({
      realm,
      subjectId: identity.subjectId,
      // The assurance the upstream actually achieved, not the one we would like it to have.
    });

    void audit.record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authentication',
      action: 'authentication.federated',
      outcome: 'success',
      subjectId: identity.subjectId,
      detail: { provider: provider.name, provisioned },
    });

    return reply.send({
      subjectId: identity.subjectId,
      sessionId: session.sessionId,
      userName: identity.userName,
      provisioned,
    });
  });

  /**
   * Turns upstream claims into local role assignments.
   *
   * Assignments made by a provider are replaced on every sign-in, so removing somebody from a group
   * upstream removes the role here at their next sign-in. Leaving stale assignments in place is how
   * a leaver keeps access nobody remembers granting.
   */
  async function applyRoleMapping(
    realmId: string,
    tenantId: string,
    subjectId: string,
    provider: IdentityProviderRecord,
    claims: Record<string, unknown>,
  ): Promise<void> {
    // The record's own shape: a list of (claim, value, roleName). Data rather than code, because
    // the alternative is this service learning what an upstream group is called, which is exactly the
    // coupling brokering exists to remove.
    const wanted = [...new Set(
      (provider.claimMappings ?? [])
        .filter((rule) => {
          const raw = claims[rule.claim];
          const held = Array.isArray(raw) ? raw.map(String) : raw === undefined ? [] : [String(raw)];
          return held.includes(rule.value);
        })
        .map((rule) => rule.roleName),
    )];

    const roles = await fastify.db.collection<RoleRecord>(ROLE_COLLECTION)
      .find({ realmId, name: { $in: wanted } }, { projection: { _id: 0, roleId: 1, name: 1 } })
      .toArray() as unknown as Array<{ roleId: string; name: string }>;

    const assignments = fastify.db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);
    await assignments.deleteMany({ realmId, subjectId, grantedBy: provider.providerId });
    if (roles.length === 0) return;

    await assignments.insertMany(roles.map((role) => ({
      realmId,
      tenantId,
      assignmentId: `assign-${randomUUID()}`,
      subjectId,
      roleId: role.roleId,
      grantedAt: new Date().toISOString(),
      // Recorded so an assignment made by federation is distinguishable from one an administrator
      // made deliberately, and so only the former is replaced at the next sign-in.
      grantedBy: provider.providerId,
      meta: newMeta('RoleAssignment'),
    })) as unknown as RoleAssignmentRecord[]);
  }
}
