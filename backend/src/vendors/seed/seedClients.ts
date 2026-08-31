import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import { v5 as uuidv5 } from 'uuid';
import { clientSecretFor } from '@leafypay/platform-links';
import {
  CLIENT_COLLECTION, REALM_COLLECTION, IDENTITY_COLLECTION, ROLE_ASSIGNMENT_COLLECTION, ROLE_COLLECTION,
  PERMISSION_COLLECTION, RESOURCE_SERVER_COLLECTION,
} from '../../shared/models/collections';
import { ClientRecord } from '../../modules/oauth/models/client.model';
import { IdentityRecord } from '../../modules/directory/models/identity.model';
import {
  RoleAssignmentRecord, RoleRecord, RolePermission, PermissionRecord, ResourceServerRecord,
} from '../../modules/authorization/models/authorization.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
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
  clientType: ClientRecord['clientType'];
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  grantTypes: ClientRecord['grantTypes'];
  scope: string;
  requirePkce: boolean;
  tokenEndpointAuthMethod: ClientRecord['tokenEndpointAuthMethod'];
  applicationType?: ClientRecord['applicationType'];
  status: ClientRecord['status'];
  backchannel?: ClientRecord['backchannel'];
  demoRoster?: string[];
  owner?: { kind: string; ref: string; displayName?: string };
  /** Present when this client is a principal in its own right rather than an application's agent. */
  serviceIdentity?: {
    kind: IdentityRecord['kind'];
    userName: string;
    roleName?: string;
    owner?: { kind: string; ref: string; displayName?: string };
    /** Which resource server the permissions below belong to. */
    resourceServer?: string;
    permissions?: Record<string, string[]>;
  };
}

export async function seedClients(db: Db): Promise<void> {
  const fixtures = readSeedFile<ClientFixture[]>('clients.json');

  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray() as unknown as Array<{ realmId: string; name: string }>;
  const realmIdByName = new Map(realms.map((realm) => [realm.name, realm.realmId]));

  const clients = db.collection<ClientRecord>(CLIENT_COLLECTION);
  const identities = db.collection<IdentityRecord>(IDENTITY_COLLECTION);
  const assignments = db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);
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

    await upsertSeed<ClientRecord>(
      clients,
      { realmId, clientId: fixture.clientId },
      {
        clientName: fixture.clientName,
        clientType: fixture.clientType,
        // Derived from the client id, then hashed. The fixture says WHETHER a client is confidential
        // and never what its secret is: a literal in a checked-in file is indistinguishable from a
        // leaked credential, to a scanner and to a reader. What is STORED is the hash either way.
        ...(clientSecret
          ? {
            clientSecretHash: await bcrypt.hash(clientSecret, 12),
            clientSecretPrefix: clientSecret.slice(0, 8),
          }
          : {}),
        redirectUris: fixture.redirectUris,
        ...(fixture.postLogoutRedirectUris ? { postLogoutRedirectUris: fixture.postLogoutRedirectUris } : {}),
        grantTypes: fixture.grantTypes,
        scope: fixture.scope,
        requirePkce: fixture.requirePkce,
        tokenEndpointAuthMethod: fixture.tokenEndpointAuthMethod,
        ...(fixture.applicationType ? { applicationType: fixture.applicationType } : {}),
        ...(fixture.backchannel ? { backchannel: fixture.backchannel } : {}),
        ...(fixture.demoRoster ? { demoRoster: fixture.demoRoster } : {}),
        ...(fixture.owner ? { owner: fixture.owner } : {}),
        status: fixture.status,
      },
      { realmId, tenantId: DEFAULT_TENANT_ID, clientId: fixture.clientId },
      'Client',
    );
    clientCount += 1;

    if (!fixture.serviceIdentity) continue;

    // The machine's own principal record, keyed by the client id it authenticates as.
    await upsertSeed<IdentityRecord>(
      identities,
      { subjectId: fixture.clientId },
      {
        userName: fixture.serviceIdentity.userName,
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
    await upsertSeed<ResourceServerRecord>(
      db.collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION),
      { resourceServerId: serverId },
      { name: serverName, audience: serverName, permissionCatalogVersion: '0', validationMode: 'hybrid', registeredAt: now },
      { resourceServerId: serverId, realmId, tenantId: DEFAULT_TENANT_ID },
      'ResourceServer',
    );

    const held: RolePermission[] = [];
    for (const [resource, actions] of Object.entries(fixture.serviceIdentity.permissions ?? {})) {
      for (const action of actions) {
        const permissionId = uuidv5(`permission:${serverId}:${resource}:${action}`, AUTHORIZATION_NAMESPACE);
        await upsertSeed<PermissionRecord>(
          db.collection<PermissionRecord>(PERMISSION_COLLECTION),
          { permissionId },
          { resourceServerId: serverId, resource, action, description: `${action} on ${resource}` },
          { permissionId, resourceServerId: serverId, realmId, tenantId: DEFAULT_TENANT_ID },
          'Permission',
        );
        held.push({ resourceServerId: serverId, resource, action });
      }
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

    const assignmentId = uuidv5(`service-assignment:${fixture.clientId}`, CLIENT_NAMESPACE);
    await upsertSeed<RoleAssignmentRecord>(
      assignments,
      { assignmentId },
      { subjectId: fixture.clientId, roleId, grantedAt: now },
      { assignmentId, subjectId: fixture.clientId, roleId, realmId, tenantId: DEFAULT_TENANT_ID },
      'RoleAssignment',
    );
  }

  console.log(`  client: ${clientCount}`);
  console.log(`  identity: ${serviceCount} service principal(s)`);
}
