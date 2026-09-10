import { Db } from 'mongodb';
import { v5 as uuidv5 } from 'uuid';
import {
  RESOURCE_COLLECTION, ROLE_COLLECTION,
  PRINCIPAL_COLLECTION, REALM_COLLECTION,
} from '../../shared/models/collections';
import { RoleRecord, DenialRationale } from '../../modules/authorization/models/authorization.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { PrincipalRecord } from '../../modules/directory/models/principal.model';
import { upsertSeed, upsertHolding, SEED_GRANTED_AT } from './upsertSeed';
import { readSeedFile } from './readSeedFile';
import { ResourceRecord, permissionString } from '../../modules/authorization/models/resource.model';

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
  /**
   * Roles held in the principal's OWN realm that grant administration of another one.
   *
   * The record stays where the principal is, and its scope names the realm it reaches. That is what
   * lets somebody administer two realms without existing in two, which would mean two identities, two
   * credentials and a token each realm would have to decide whether to trust.
   */
  realmGrants?: Array<{ realm: string; roleName: string; justification?: string }>;
}

/** The authority's own resource server, so administering it is a permission like any other. */
const AUTHORITY_RESOURCE_SERVER = 'authority';

function resourceId(realmId: string, name: string): string {
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

/** Distinct from the unscoped one, so a principal can hold the same role at home and abroad. */
function realmGrantId(subjectId: string, role: string, targetRealmId: string): string {
  return uuidv5(`assignment:${subjectId}:${role}:realm:${targetRealmId}`, AUTHORIZATION_NAMESPACE);
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

  const servers = db.collection<ResourceRecord>(RESOURCE_COLLECTION);
  const roles = db.collection<RoleRecord>(ROLE_COLLECTION);
  const principals = db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION);

  const now = new Date().toISOString();
  const seenServers = new Set<string>();
  let roleCount = 0;

  async function ensureServer(realmId: string, name: string, audience: string): Promise<string> {
    const id = resourceId(realmId, name);
    if (seenServers.has(id)) return id;
    seenServers.add(id);
    await upsertSeed<ResourceRecord>(
      servers,
      { resourceId: id },
      {
        name,
        audience,
        kind: 'api',
        catalogVersion: 0,
        // Filled in P5 from the permissions this resource declares: the catalog is what a policy
        // naming this resource is validated against.
        actions: [],
        status: 'active',
        // Verify locally on every request, consult the authority where the decision is expensive to
        // get wrong. Neither model is right in general, so the choice is the resource's.
        validationMode: 'hybrid',
        registeredAt: SEED_GRANTED_AT,
      },
      { resourceId: id, realmId, tenantId: DEFAULT_TENANT_ID },
      'ResourceServer',
    );
    return id;
  }

  /**
   * The action catalog for one resource TYPE, as a resource parented to its API.
   *
   * A permission is the string `type:action`, so the type has to be a resource in its own right for
   * the audience to know which types it enforces. Declared as a BLOCK: the fixture states the whole
   * set of verbs, and that is what the catalog becomes.
   */
  const actionsByType = new Map<string, { serverId: string; realmId: string; actions: Set<string> }>();

  function declareAction(realmId: string, serverId: string, resource: string, action: string): void {
    const key = `${serverId}:${resource}`;
    const held = actionsByType.get(key) ?? { serverId, realmId, actions: new Set<string>() };
    held.actions.add(action);
    actionsByType.set(key, held);
  }

  async function writeCatalogs(): Promise<number> {
    let types = 0;
    for (const [key, entry] of actionsByType) {
      const type = key.slice(entry.serverId.length + 1);
      const id = uuidv5(`resource:${entry.realmId}:${entry.serverId}:${type}`, AUTHORIZATION_NAMESPACE);
      await upsertSeed<ResourceRecord>(
        servers,
        { resourceId: id },
        {
          name: type,
          actions: [...entry.actions].sort(),
          catalogVersion: 1,
          status: 'active',
        },
        {
          resourceId: id,
          realmId: entry.realmId,
          tenantId: DEFAULT_TENANT_ID,
          // An object the API protects, reached through it rather than by an audience of its own.
          kind: 'object',
          parentResourceId: entry.serverId,
          registeredAt: SEED_GRANTED_AT,
        },
        'Resource',
      );
      types += 1;
    }
    return types;
  }

  for (const fixture of roleFixtures) {
    const realmId = realmIdByName.get(fixture.realm);
    if (!realmId) throw new Error(`roles.json names realm "${fixture.realm}", which is not seeded`);

    const applicationServer = await ensureServer(realmId, fixture.resourceServer, fixture.resourceServer);
    const authorityServer = await ensureServer(realmId, AUTHORITY_RESOURCE_SERVER, AUTHORITY_RESOURCE_SERVER);

    // Permission STRINGS, the same spelling a policy uses and a token carries.
    const held: string[] = [];
    for (const [resource, actions] of Object.entries(fixture.permissions)) {
      for (const action of actions) {
        declareAction(realmId, applicationServer, resource, action);
        held.push(permissionString(resource, action));
      }
    }
    for (const [resource, actions] of Object.entries(fixture.authorityPermissions ?? {})) {
      for (const action of actions) {
        declareAction(realmId, authorityServer, resource, action);
        held.push(permissionString(resource, action));
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
  let crossRealm = 0;
  for (const identity of identityFixtures) {
    for (const grant of identity.realmGrants ?? []) {
      const homeRealmId = realmIdByName.get(identity.realm);
      const targetRealmId = realmIdByName.get(grant.realm);
      if (!homeRealmId) throw new Error(`${identityFixtureName} grants from realm "${identity.realm}", which is not seeded`);
      if (!targetRealmId) throw new Error(`${identityFixtureName} grants administration of realm "${grant.realm}", which is not seeded`);
      // Pointing a grant at its own realm would be a second way to say what an ordinary assignment
      // already says, and the two would then be able to disagree.
      if (homeRealmId === targetRealmId) throw new Error(`${identityFixtureName} grants ${identity.subjectId} their own realm`);
      // The ROLE is the home realm's, because a realm does not get to name another realm's roles.
      const known = roleFixtures.some((role) => role.name === grant.roleName && role.realm === identity.realm);
      if (!known) throw new Error(`${identityFixtureName} grants unknown role "${grant.roleName}" in realm "${identity.realm}"`);

      await upsertHolding(
        principals,
        { realmId: homeRealmId, subjectId: identity.subjectId },
        {
          roleId: roleId(homeRealmId, grant.roleName),
          scope: { kind: 'realm', ref: targetRealmId },
          grantedAt: SEED_GRANTED_AT,
          ...(grant.justification ? { justification: grant.justification } : {}),
        },
      );
      crossRealm += 1;
    }

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

    await upsertHolding(
      principals,
      { realmId, subjectId: identity.subjectId },
      {
        roleId: id,
        grantedAt: SEED_GRANTED_AT,
        // No expiry: a permanent holding. An elevation carries one, and that single difference is
        // what makes the same entry shape serve both.
      },
    );
    assigned += 1;
  }

  /**
   * The realm administrator, and the permissions the console's own screens enforce.
   *
   * Appended rather than folded into the fixtures because these are permissions over the AUTHORITY'S
   * own objects, which no application's catalog declares and therefore no fixture naming a resource
   * server can carry. Registering them here means the console's roles, keys and sessions screens are
   * reachable in a fresh install rather than after somebody edits data.
   *
   * Two tiers have to be demonstrable without editing anything, so this role is deliberately NOT
   * given to everyone: the account-holder roles in both fixture sets carry no authority permission at
   * all, and stay that way.
   */
  const ADMINISTRATOR_ROLE = 'realm_administrator';

  // Reading a key set, adding a key and withdrawing one are three different authorities. Rotation
  // takes nothing away; retirement stops publication and every token already signed stops verifying.
  const ADMINISTRATOR_PERMISSIONS: Record<string, string[]> = {
    roles: ['view', 'manage'],
    assignments: ['view', 'manage'],
    // `manage` declares or edits a resource server's own catalog from the console (the same write
    // `PUT /admin/resource-servers/:name/permissions` already offers admin-token callers); `view` is
    // reading what is already declared, the tier `/permissions` and the read side of the resource
    // catalog both ask for.
    permissions: ['view', 'manage'],
    // Reading a policy and writing one are separate authorities, because a statement that DENIES is
    // withdrawn by the same verb that adds one, and reviewing the rules is not the same standing as
    // changing them.
    policies: ['view', 'manage'],
    sessions: ['view', 'manage'],
    keys: ['view', 'rotate', 'retire'],
  };

  let administrators = 0;
  for (const [realmName, realmId] of realmIdByName) {
    // Only realms this fixture set actually describes: the seeder runs once per population, and a
    // realm it says nothing about is not this run's to administer.
    if (!roleFixtures.some((fixture) => fixture.realm === realmName)) continue;

    const authorityServer = await ensureServer(realmId, AUTHORITY_RESOURCE_SERVER, AUTHORITY_RESOURCE_SERVER);
    const held: string[] = [];
    for (const [resource, actions] of Object.entries(ADMINISTRATOR_PERMISSIONS)) {
      for (const action of actions) {
        declareAction(realmId, authorityServer, resource, action);
        held.push(permissionString(resource, action));
      }
    }

    await upsertSeed<RoleRecord>(
      roles,
      { roleId: roleId(realmId, ADMINISTRATOR_ROLE) },
      {
        name: ADMINISTRATOR_ROLE,
        displayName: 'Realm administrator',
        description:
          'Administers one authentication domain: the principals registered in it, the roles and '
          + 'permissions they hold, its signing keys and its sessions.',
        permissions: held,
        // Realm wide by definition. The whole point of the tier is reaching records that are not
        // the holder's own, and a self-scoped administrator would be a contradiction.
        scopeKind: 'all',
        builtin: true,
        sodRationale:
          'Kept separate from the roles that administer an application\'s own data, so administering '
          + 'identity is a distinct grant that can be reviewed and withdrawn on its own.',
      },
      { roleId: roleId(realmId, ADMINISTRATOR_ROLE), realmId, tenantId: DEFAULT_TENANT_ID },
      'Role',
    );

    // Given to whoever this population already treats as the realm's administrator, so the demo has
    // a principal who can open every screen without a subject identifier being written down here.
    const administrativeRoles = new Set(
      roleFixtures
        .filter((fixture) => fixture.realm === realmName && (fixture.authorityPermissions?.roles ?? []).includes('manage'))
        .map((fixture) => fixture.name),
    );
    for (const identity of identityFixtures) {
      if (identity.realm !== realmName || !identity.roleName) continue;
      if (!administrativeRoles.has(identity.roleName)) continue;

      await upsertHolding(
        principals,
        { realmId, subjectId: identity.subjectId },
        { roleId: roleId(realmId, ADMINISTRATOR_ROLE), grantedAt: SEED_GRANTED_AT },
      );
      administrators += 1;
    }
  }

  // Written after every role, because the catalog is the union of what the fixtures declare and it
  // is only complete once they have all been read.
  const types = await writeCatalogs();
  console.log(`  resource: ${seenServers.size} api, ${types} object`);
  console.log(`  role: ${roleCount}`);
  console.log(`  roleHolding: ${assigned} (+${crossRealm} naming another realm)`);
  console.log(`  realmAdministrator: ${administrators}`);
}
