import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import { v5 as uuidv5 } from 'uuid';
import { clientSecretFor } from '@leafypay/platform-links';
import {
  CREDENTIAL_COLLECTION, REALM_COLLECTION, PRINCIPAL_COLLECTION, ROLE_COLLECTION,
  RESOURCE_COLLECTION,
} from '../../shared/models/collections';
import { OAuthClient } from '../../modules/oauth/models/client.model';
import { PrincipalRecord } from '../../modules/directory/models/principal.model';
import { RoleRecord } from '../../modules/authorization/models/authorization.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed, upsertHolding, SEED_GRANTED_AT } from './upsertSeed';
import { CredentialRecord } from '../../modules/directory/models/credential.model';
import { ResourceRecord, permissionString } from '../../modules/authorization/models/resource.model';
import { clientMetadata } from '../../modules/oauth/models/client.model';
import { readSeedFile } from './readSeedFile';

/**
 * OAuth clients, and the service identities behind the machine ones.
 *
 * A machine principal gets a full identity record here, not a bare credential. It has an owner, a
 * lifecycle, an assurance level and an audit trail, because the absence of exactly those is what
 * turns service accounts into the permanent, unattributable credentials every audit finds. It also
 * means a permission can be granted to a service the same way it is granted to a person, through the
 * same roles and the same decision point.
 */

const CLIENT_NAMESPACE = 'c7e2b9a4-1f6d-4b8e-9c3a-5d0f2e7b1a64';

// The same namespace the authorization seeder uses, so a resource server and a permission created
// from either side resolve to one record rather than two that look alike.
const AUTHORIZATION_NAMESPACE = 'a1c4e7b2-5d9f-4a3c-8e6b-2f7d1c9a4b83';

interface ClientFixture {
  realm: string;
  clientId: string;
  clientName: string;
  clientType: OAuthClient['clientType'];
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  grantTypes: OAuthClient['grantTypes'];
  scope: string;
  requirePkce: boolean;
  tokenEndpointAuthMethod: OAuthClient['tokenEndpointAuthMethod'];
  applicationType?: OAuthClient['applicationType'];
  status: OAuthClient['status'];
  backchannel?: OAuthClient['backchannel'];
  demoRoster?: string[];
  /** Which resource servers a token for this client is addressed to. Declared, never inferred. */
  audience?: string[];
  /** Only the authority's own console. Absent means the client asks for consent. */
  firstParty?: boolean;
  /** A set: every owner administers the registration equally, and there is never zero of them. */
  owners?: Array<{ kind: string; ref: string; displayName?: string }>;
  /** Present when this client is a principal in its own right rather than an application's agent. */
  serviceIdentity?: {
    kind: PrincipalRecord['kind'];
    /**
     * The NAME to show. The login is the `clientId`, and is not repeated here.
     *
     * It was `userName`, holding strings like "LeafyPay, as a registered third party": a display
     * name in the field that carries the unique login index, which is the same defect the human
     * fixtures had. A machine's identifier is the client id it authenticates as, which is already
     * this record's `subjectId`.
     */
    displayName: string;
    roleName?: string;
    owner?: { kind: string; ref: string; displayName?: string };
    /** Which resource server the permissions below belong to. */
    resourceServer?: string;
    permissions?: Record<string, string[]>;
  };
  /**
   * What this client's resource server tells a person each scope means.
   *
   * On the fixture because the vocabulary is the deployment's. `required` marks a scope the flow
   * cannot proceed without, which is `openid` and, in practice, nothing else.
   */
  scopeDescriptions?: Array<{ name: string; description: string; required?: boolean }>;
}

export async function seedClients(db: Db): Promise<void> {
  const fixtures = readSeedFile<ClientFixture[]>('clients.json');

  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray() as unknown as Array<{ realmId: string; name: string }>;
  const realmIdByName = new Map(realms.map((realm) => [realm.name, realm.realmId]));

  const clients = db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
  const identities = db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION);

  const roles = db.collection<RoleRecord>(ROLE_COLLECTION);

  const now = new Date().toISOString();
  let clientCount = 0;
  let serviceCount = 0;

  for (const fixture of fixtures) {
    const realmId = realmIdByName.get(fixture.realm);
    if (!realmId) throw new Error(`clients.json names realm "${fixture.realm}", which is not seeded`);

    // Whether a client HAS a secret is what the fixture states; what that secret IS comes from the
    // shared derivation, which every presenting caller uses too.
    const clientSecret = fixture.clientType === 'confidential'
      ? clientSecretFor(fixture.clientId)
      : undefined;

    /**
     * A client registration is a credential of type `oauth_client`.
     *
     * The hash goes in ON INSERT ONLY, never as a field the seeder owns and compares. bcrypt salts
     * randomly, so a freshly computed hash never equals the stored one and treating it as owned made
     * every reseed rewrite every client. The secret itself is derived from the client id, so
     * re-hashing buys nothing: what matters is that the stored hash verifies.
     */
    await upsertSeed<CredentialRecord>(
      clients,
      { realmId, clientId: fixture.clientId, type: 'oauth_client' },
      {
        // Owned and compared: the registration metadata, which a fixture edit should propagate.
        metadata: clientMetadata({
          clientName: fixture.clientName,
          clientType: fixture.clientType,
          redirectUris: fixture.redirectUris,
          ...(fixture.postLogoutRedirectUris ? { postLogoutRedirectUris: fixture.postLogoutRedirectUris } : {}),
          grantTypes: fixture.grantTypes as OAuthClient['grantTypes'],
          scope: fixture.scope,
          requirePkce: fixture.requirePkce,
          tokenEndpointAuthMethod: fixture.tokenEndpointAuthMethod,
          ...(fixture.applicationType ? { applicationType: fixture.applicationType } : {}),
          ...(fixture.backchannel ? { backchannel: fixture.backchannel } : {}),
          ...(fixture.demoRoster ? { demoRoster: fixture.demoRoster } : {}),
          ...(fixture.audience ? { audience: fixture.audience } : {}),
          ...(fixture.firstParty ? { firstParty: fixture.firstParty } : {}),
        }),
        ...(fixture.owners?.length ? { administrators: fixture.owners } : {}),
        status: fixture.status,
      },
      {
        realmId,
        tenantId: DEFAULT_TENANT_ID,
        credentialId: uuidv5(`oauth-client:${realmId}:${fixture.clientId}`, CLIENT_NAMESPACE),
        subjectId: fixture.clientId,
        type: 'oauth_client',
        clientId: fixture.clientId,
        // The principal the client acts as. A service client is its own subject.
        ownerId: fixture.clientId,
        // The fixture says WHETHER a client is confidential and never what its secret is: a literal
        // in a checked-in file is indistinguishable from a leaked credential, to a scanner and to a
        // reader. What is STORED is the hash either way.
        ...(clientSecret
          ? {
            hash: await bcrypt.hash(clientSecret, 12),
            secretPrefix: clientSecret.slice(0, 8),
          }
          : {}),
        assurance: { level: 'aal1', method: 'client_secret' },
        createdAt: SEED_GRANTED_AT,
      },
      'Credential',
    );
    clientCount += 1;

    if (!fixture.serviceIdentity) continue;

    // The machine's own principal record, keyed by the client id it authenticates as.
    await upsertSeed<PrincipalRecord>(
      identities,
      { subjectId: fixture.clientId },
      {
        // The login is the client id: unique in the realm, already this record's subject, and an
        // identifier rather than a sentence.
        userName: fixture.clientId,
        name: { formatted: fixture.serviceIdentity.displayName },
        kind: fixture.serviceIdentity.kind,
        active: true,
        lifecycleState: 'active',
        sessionEpoch: 0,
        ...(fixture.serviceIdentity.owner ? { owner: fixture.serviceIdentity.owner } : {}),
      },
      { subjectId: fixture.clientId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Identity',
    );
    serviceCount += 1;

    if (!fixture.serviceIdentity.roleName) continue;

    // The permissions a machine holds, on the resource server that enforces them.
    //
    // Ordinary catalog rows, identical in shape to an application's, so the decision point resolves a
    // service exactly as it resolves a person. That is the point of granting one at all: if a machine
    // needed its own mechanism, the two halves would be free to drift and one of them would end up
    // without an audit trail.
    const serverName = fixture.serviceIdentity.resourceServer ?? fixture.realm;
    const serverId = uuidv5(`resource-server:${realmId}:${serverName}`, AUTHORIZATION_NAMESPACE);

    // The resource server, if the roles seeder has not already created it. A permission pointing at a
    // server that does not exist is unenforceable and invisible: the decision point could not scope
    // it to an audience, so it would silently travel in every token instead of one.
    await upsertSeed<ResourceRecord>(
      db.collection<ResourceRecord>(RESOURCE_COLLECTION),
      { resourceId: serverId },
      {
        name: serverName,
        audience: serverName,
        kind: 'api',
        catalogVersion: 0,
        actions: [],
        // What each scope MEANS, from the fixture. A consent screen that lists `payments:read` and
        // asks for agreement has obtained a click rather than consent.
        ...(fixture.scopeDescriptions ? { scopes: fixture.scopeDescriptions } : {}),
        status: 'active',
        validationMode: 'hybrid',
        registeredAt: SEED_GRANTED_AT,
      },
      { resourceId: serverId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Resource',
    );

    /**
     * The machine's permissions, as strings, with each resource TYPE declared as a resource.
     *
     * Ordinary catalog entries, identical in shape to an application's, so the decision point
     * resolves a service exactly as it resolves a person. That is the point of granting one at all:
     * if a machine needed its own mechanism, the two halves would drift and one would end up wrong.
     */
    const held: string[] = [];
    const actionsByType = new Map<string, Set<string>>();
    for (const [resource, actions] of Object.entries(fixture.serviceIdentity.permissions ?? {})) {
      for (const action of actions) {
        const declared = actionsByType.get(resource) ?? new Set<string>();
        declared.add(action);
        actionsByType.set(resource, declared);
        held.push(permissionString(resource, action));
      }
    }
    for (const [type, actions] of actionsByType) {
      /**
       * Keyed on the server's ID, matching `seedAuthorization`.
       *
       * This derived from the server NAME while the roles seeder derived from its uuid, so the same
       * logical resource was written twice under two different ids. The published catalog then
       * listed five enforcement points twice, and worse, the two documents each owned their own
       * `actions`: which verbs a resource declared depended on which of the two a reader happened
       * to load. One derivation, in both places, or they drift again.
       */
      const childId = uuidv5(`resource:${realmId}:${serverId}:${type}`, AUTHORIZATION_NAMESPACE);
      await upsertSeed<ResourceRecord>(
        db.collection<ResourceRecord>(RESOURCE_COLLECTION),
        { resourceId: childId },
        { name: type, actions: [...actions].sort(), catalogVersion: 1, status: 'active' },
        {
          resourceId: childId,
          realmId,
          tenantId: DEFAULT_TENANT_ID,
          kind: 'object',
          parentResourceId: serverId,
          registeredAt: SEED_GRANTED_AT,
        },
        'Resource',
      );
    }

    // The role a service holds, named for what the machine does rather than for who it is.
    const roleId = uuidv5(`service-role:${realmId}:${fixture.serviceIdentity.roleName}`, CLIENT_NAMESPACE);
    await upsertSeed<RoleRecord>(
      roles,
      { roleId },
      {
        name: fixture.serviceIdentity.roleName,
        displayName: fixture.serviceIdentity.roleName.replace(/_/g, ' '),
        description: 'Held by a non-human principal. Resolved through the same decision point as any other role.',
        permissions: held,
        scopeKind: 'all',
        builtin: true,
        sodRationale:
          'A machine identity is never a second-class record. It has an owner, a lifecycle and an '
          + 'audit trail, and its authority is a role like anyone else\'s rather than an implicit '
          + 'consequence of holding a credential.',
      },
      { roleId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Role',
    );

    // The service principal holds its role like anyone else: authority is never an implicit
    // consequence of holding a credential.
    await upsertHolding(
      identities,
      { realmId, subjectId: fixture.clientId },
      { roleId, grantedAt: SEED_GRANTED_AT },
    );
  }

  console.log(`  client: ${clientCount}`);
  console.log(`  identity: ${serviceCount} service principal(s)`);
}
