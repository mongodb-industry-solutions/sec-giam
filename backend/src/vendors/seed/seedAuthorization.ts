import { Db } from 'mongodb';
import { v5 as uuidv5 } from 'uuid';
import {
  RESOURCE_SERVER_COLLECTION, PERMISSION_COLLECTION, ROLE_COLLECTION,
  ROLE_ASSIGNMENT_COLLECTION, REALM_COLLECTION,
} from '../../shared/models/collections';
import {
  ResourceServerRecord, PermissionRecord, RoleRecord, RoleAssignmentRecord, RolePermission, DenialRationale,
} from '../../modules/authorization/models/authorization.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';

/**
 * Roles, the permissions they hold, and who holds them.
 *
 * The permission CATALOG is not seeded from here. A resource server ships its enforcement points in
 * its own code and registers them at boot, because only the code that enforces a permission can say
 * the permission exists. What is seeded here is the assignment, which is the authority's half.
 *
 * The catalog rows this seeder does create are the ones implied by the roles: a role naming a
 * permission its resource server has not registered yet would be unenforceable and invisible, and a
 * fresh database would have roles that grant nothing until an application happened to start.
 */

const AUTHORIZATION_NAMESPACE = 'a1c4e7b2-5d9f-4a3c-8e6b-2f7d1c9a4b83';

interface RoleFixture {
  realm: string;
  resourceServer: string;
  name: string;
  displayName: string;
  description: string;
  scopeKind: RoleRecord['scopeKind'];
  builtin: boolean;
  sodRationale?: string;
  permissions: Record<string, string[]>;
  /** Permissions over the authority's OWN objects, which are not an application's to grant. */
  authorityPermissions?: Record<string, string[]>;
  denialRationale?: DenialRationale[];
}

interface IdentityFixture {
  realm: string;
  subjectId: string;
  roleName?: string;
}

/** The authority's own resource server, so administering it is a permission like any other. */
const AUTHORITY_RESOURCE_SERVER = 'authority';

function resourceServerId(realmId: string, name: string): string {
  return uuidv5(`resource-server:${realmId}:${name}`, AUTHORIZATION_NAMESPACE);
}

function permissionId(serverId: string, resource: string, action: string): string {
  return uuidv5(`permission:${serverId}:${resource}:${action}`, AUTHORIZATION_NAMESPACE);
}

function roleId(realmId: string, name: string): string {
  return uuidv5(`role:${realmId}:${name}`, AUTHORIZATION_NAMESPACE);
}

function assignmentId(subjectId: string, role: string): string {
  return uuidv5(`assignment:${subjectId}:${role}`, AUTHORIZATION_NAMESPACE);
}

export async function seedAuthorization(
  db: Db,
  roleFixtureName = 'roles.json',
  identityFixtureName = 'identities.json',
): Promise<void> {
  const roleFixtures = readSeedFile<RoleFixture[]>(roleFixtureName);
  const identityFixtures = readSeedFile<IdentityFixture[]>(identityFixtureName);

  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray() as unknown as Array<{ realmId: string; name: string }>;
  const realmIdByName = new Map(realms.map((realm) => [realm.name, realm.realmId]));

  const servers = db.collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION);
  const permissions = db.collection<PermissionRecord>(PERMISSION_COLLECTION);
  const roles = db.collection<RoleRecord>(ROLE_COLLECTION);
  const assignments = db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);

  const now = new Date().toISOString();
  const seenServers = new Set<string>();
  const seenPermissions = new Set<string>();
  let roleCount = 0;

  async function ensureServer(realmId: string, name: string, audience: string): Promise<string> {
    const id = resourceServerId(realmId, name);
    if (seenServers.has(id)) return id;
    seenServers.add(id);
    await upsertSeed<ResourceServerRecord>(
      servers,
      { resourceServerId: id },
      {
        name,
        audience,
        permissionCatalogVersion: '0',
        // Verify locally on every request, consult the authority where the decision is expensive to
        // get wrong. Neither model is right in general, so the choice is the resource server's.
        validationMode: 'hybrid',
        registeredAt: now,
      },
      { resourceServerId: id, realmId, tenantId: DEFAULT_TENANT_ID },
      'ResourceServer',
    );
    return id;
  }

  async function ensurePermission(
    realmId: string,
    serverId: string,
    resource: string,
    action: string,
  ): Promise<void> {
    const id = permissionId(serverId, resource, action);
    if (seenPermissions.has(id)) return;
    seenPermissions.add(id);
    await upsertSeed<PermissionRecord>(
      permissions,
      { permissionId: id },
      {
        resourceServerId: serverId,
        resource,
        action,
        description: `${action} on ${resource}`,
      },
      { permissionId: id, resourceServerId: serverId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Permission',
    );
  }

  for (const fixture of roleFixtures) {
    const realmId = realmIdByName.get(fixture.realm);
    if (!realmId) throw new Error(`roles.json names realm "${fixture.realm}", which is not seeded`);

    const applicationServer = await ensureServer(realmId, fixture.resourceServer, fixture.resourceServer);
    const authorityServer = await ensureServer(realmId, AUTHORITY_RESOURCE_SERVER, AUTHORITY_RESOURCE_SERVER);

    const held: RolePermission[] = [];
    for (const [resource, actions] of Object.entries(fixture.permissions)) {
      for (const action of actions) {
        await ensurePermission(realmId, applicationServer, resource, action);
        held.push({ resourceServerId: applicationServer, resource, action });
      }
    }
    for (const [resource, actions] of Object.entries(fixture.authorityPermissions ?? {})) {
      for (const action of actions) {
        await ensurePermission(realmId, authorityServer, resource, action);
        held.push({ resourceServerId: authorityServer, resource, action });
      }
    }

    await upsertSeed<RoleRecord>(
      roles,
      { roleId: roleId(realmId, fixture.name) },
      {
        name: fixture.name,
        displayName: fixture.displayName,
        description: fixture.description,
        permissions: held,
        scopeKind: fixture.scopeKind,
        builtin: fixture.builtin,
        // Compliance evidence, carried WITH the role it constrains rather than left in a comment in
        // the code that seeded it. An auditor asking why a role lacks something deserves an answer
        // from the system, and an absence with no recorded reason reads as an oversight.
        ...(fixture.sodRationale ? { sodRationale: fixture.sodRationale } : {}),
        ...(fixture.denialRationale ? { denialRationale: fixture.denialRationale } : {}),
      },
      { roleId: roleId(realmId, fixture.name), realmId, tenantId: DEFAULT_TENANT_ID },
      'Role',
    );
    roleCount += 1;
  }

  let assigned = 0;
  for (const identity of identityFixtures) {
    if (!identity.roleName) continue;
    const realmId = realmIdByName.get(identity.realm);
    if (!realmId) continue;
    const id = roleId(realmId, identity.roleName);
    const known = roleFixtures.some(
      (role) => role.name === identity.roleName && role.realm === identity.realm,
    );
    // A principal assigned a role that does not exist would hold nothing while appearing to hold
    // something, which is the worst of both: the interface shows a role and every check denies.
    if (!known) {
      throw new Error(`${identityFixtureName} assigns unknown role "${identity.roleName}" in realm "${identity.realm}"`);
    }

    await upsertSeed<RoleAssignmentRecord>(
      assignments,
      { assignmentId: assignmentId(identity.subjectId, identity.roleName) },
      {
        subjectId: identity.subjectId,
        roleId: id,
        grantedAt: now,
        // No expiry: a permanent assignment. An elevation carries one, and that single difference is
        // what makes the same record type serve both.
      },
      {
        assignmentId: assignmentId(identity.subjectId, identity.roleName),
        subjectId: identity.subjectId,
        roleId: id,
        realmId,
        tenantId: DEFAULT_TENANT_ID,
      },
      'RoleAssignment',
    );
    assigned += 1;
  }

  console.log(`  resourceServer: ${seenServers.size}`);
  console.log(`  permission: ${seenPermissions.size}`);
  console.log(`  role: ${roleCount}`);
  console.log(`  roleAssignment: ${assigned}`);
}
