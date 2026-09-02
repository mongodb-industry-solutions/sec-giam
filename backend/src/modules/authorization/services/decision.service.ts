import { Db } from 'mongodb';
import {
  ROLE_COLLECTION, PRINCIPAL_COLLECTION, RESOURCE_SERVER_COLLECTION, REALM_COLLECTION,
} from '../../../shared/models/collections';
import {
  RoleRecord, ResourceServerRecord, EffectivePermission, permissionKey,
  AdministrableRealm, holdingAppliesIn, REALM_SCOPE_KIND,
} from '../models/authorization.model';
import {
  PrincipalRecord, RoleHolding, activeHoldings,
} from '../../directory/models/principal.model';

/**
 * The decision point: what a principal may actually do, right now.
 *
 * Resolved at issuance and written into the token, so a resource server verifies a signature and
 * reads a claim rather than calling here on every request. That is what keeps the authority off the
 * hot path and what stops it becoming the single point of failure the platform does not have today.
 *
 * The cost is that a permission change reaches a live token only when the next one is issued, which
 * is why access-token lifetimes are short and why the irreversible operations introspect instead.
 * Both halves of that trade are deliberate and neither is hidden.
 *
 * A principal has ONE home realm, which is where their identity and credentials live and which
 * issues their tokens. Administering a second realm is a grant held at home and pointed elsewhere,
 * never a second identity and never a token that two realms would both accept.
 */
export class DecisionService {
  constructor(private readonly db: Db) {}

  /**
   * Live role holdings for a subject, read from the principal that holds them.
   *
   * ONE read, which is the point of embedding them: this is the hottest path in the system and the
   * referenced form was two reads plus a traversal.
   *
   * Expiry is judged here rather than left to the sweep, and that ordering is the correctness
   * argument rather than an optimisation: a TTL index cannot reach an array element, so an expired
   * holding is still physically present until a sweeper removes it. A time-bound elevation must stop
   * granting the moment it lapses, not whenever the database next gets round to it.
   */
  private async liveHoldings(realmId: string, subjectId: string): Promise<RoleHolding[]> {
    const principal = await this.db
      .collection<PrincipalRecord>(PRINCIPAL_COLLECTION)
      .findOne({ realmId, subjectId }, { projection: { _id: 0, roles: 1 } });
    if (!principal) return [];
    return activeHoldings(principal);
  }

  /**
   * Roles held, including those inherited through composition.
   *
   * Resolved with a graph traversal in the database rather than by repeated round trips, which is
   * the concrete reason a document store suits this: the relational equivalent is a recursive join
   * written once per query shape.
   */
  private async resolveRoles(realmId: string, roleIds: string[]): Promise<RoleRecord[]> {
    if (roleIds.length === 0) return [];
    return this.db.collection<RoleRecord>(ROLE_COLLECTION).aggregate<RoleRecord>([
      { $match: { realmId, roleId: { $in: roleIds } } },
      {
        $graphLookup: {
          from: ROLE_COLLECTION,
          startWith: '$parentRoleIds',
          connectFromField: 'parentRoleIds',
          connectToField: 'roleId',
          as: 'inherited',
          // Bounded, because an accidental cycle in role composition would otherwise be an
          // unbounded traversal on the token path.
          maxDepth: 8,
        },
      },
      { $project: { _id: 0 } },
    ]).toArray();
  }

  /**
   * The permissions a principal holds on ONE resource server.
   *
   * Scoped to the audience deliberately. A token carries only what its audience enforces, so a
   * principal's authority at one application never travels inside a token meant for another, and the
   * claim stays small enough to belong in a token at all.
   */
  async effectivePermissions(
    realmId: string,
    subjectId: string,
    audience: string,
  ): Promise<{ permissions: EffectivePermission[]; roles: string[]; scopeKind: 'self' | 'all' }> {
    return this.effectivePermissionsIn(realmId, subjectId, audience, realmId);
  }

  /**
   * The same question, asked about a realm the principal is not IN.
   *
   * Everything is still read from the home realm: the assignments are the principal's own, and the
   * roles they name are the home realm's roles. What the target realm decides is only WHICH of those
   * assignments count, so no record crosses the boundary and no realm's role catalog is read on
   * another realm's behalf.
   */
  async effectivePermissionsIn(
    homeRealmId: string,
    subjectId: string,
    audience: string,
    targetRealmId: string,
  ): Promise<{ permissions: EffectivePermission[]; roles: string[]; scopeKind: 'self' | 'all' }> {
    const server = await this.db
      .collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION)
      .findOne({ realmId: homeRealmId, audience }, { projection: { _id: 0, resourceServerId: 1 } });

    const held = await this.liveHoldings(homeRealmId, subjectId);
    const assignments = held.filter((assignment) => holdingAppliesIn(assignment, homeRealmId, targetRealmId));
    const roles = await this.resolveRoles(homeRealmId, assignments.map((assignment) => assignment.roleId));

    const composed: RoleRecord[] = [];
    for (const role of roles) {
      composed.push(role);
      const inherited = (role as RoleRecord & { inherited?: RoleRecord[] }).inherited ?? [];
      composed.push(...inherited);
    }

    const unique = new Map<string, EffectivePermission>();
    for (const role of composed) {
      for (const permission of role.permissions ?? []) {
        if (server && permission.resourceServerId !== server.resourceServerId) continue;
        unique.set(permissionKey(permission), { resource: permission.resource, action: permission.action });
      }
    }

    // The widest scope any held role grants. A principal holding both a self-scoped and a global role
    // is global: narrowing to the strictest would silently disable the role that was granted second.
    const scopeKind = composed.some((role) => role.scopeKind === 'all') ? 'all' : 'self';

    return {
      permissions: [...unique.values()].sort(
        (a, b) => a.resource.localeCompare(b.resource) || a.action.localeCompare(b.action),
      ),
      roles: [...new Set(composed.map((role) => role.name))].sort(),
      scopeKind,
    };
  }

  /** A single decision, for the paths that ask rather than read a claim. */
  async check(
    realmId: string,
    subjectId: string,
    audience: string,
    resource: string,
    action: string,
  ): Promise<{ effect: 'allow' | 'deny'; reason: string }> {
    return this.checkIn(realmId, subjectId, audience, resource, action, realmId);
  }

  /** The same decision, about a named target realm. */
  async checkIn(
    homeRealmId: string,
    subjectId: string,
    audience: string,
    resource: string,
    action: string,
    targetRealmId: string,
  ): Promise<{ effect: 'allow' | 'deny'; reason: string }> {
    const { permissions, roles } = await this.effectivePermissionsIn(
      homeRealmId, subjectId, audience, targetRealmId,
    );
    const held = permissions.some(
      (permission) => permission.resource === resource && permission.action === action,
    );
    // Default deny, and the reason names what was missing rather than saying no: a decision a log
    // cannot explain is not auditable.
    return held
      ? { effect: 'allow', reason: `granted by ${roles.join(', ') || 'an assignment'}` }
      : { effect: 'deny', reason: `no role held by this principal grants ${resource}:${action}` };
  }

  /**
   * The realms a principal holds a grant OVER, other than their own.
   *
   * Read from the assignments themselves rather than derived from a role name or a flag, so the
   * answer is always the set of grants somebody deliberately made. An empty result is the ordinary
   * case and costs one indexed read.
   */
  async grantedRealmIds(homeRealmId: string, subjectId: string): Promise<string[]> {
    const held = await this.liveHoldings(homeRealmId, subjectId);
    const named = held
      .filter((assignment) => assignment.scope?.kind === REALM_SCOPE_KIND && assignment.scope.ref)
      .map((assignment) => assignment.scope!.ref)
      .filter((realmId) => realmId !== homeRealmId);
    return [...new Set(named)].sort();
  }

  /**
   * Every realm this principal may administer, home realm first, with what they hold in each.
   *
   * The permissions are resolved per realm rather than once, because they are not the same set: a
   * grant over another realm is usually narrower than what its holder has at home, and returning one
   * list for both would invite a caller to assume otherwise.
   */
  async administrableRealms(
    homeRealmId: string,
    subjectId: string,
    audience: string,
  ): Promise<AdministrableRealm[]> {
    const targets = [homeRealmId, ...await this.grantedRealmIds(homeRealmId, subjectId)];
    const realms = await this.db
      .collection<{ realmId: string; name: string; displayName?: string; enabled?: boolean }>(REALM_COLLECTION)
      .find({ realmId: { $in: targets } }, { projection: { _id: 0, realmId: 1, name: 1, displayName: 1, enabled: 1 } })
      .toArray();

    const resolved: AdministrableRealm[] = [];
    for (const realmId of targets) {
      const realm = realms.find((candidate) => candidate.realmId === realmId);
      // A grant naming a realm that no longer exists, or one that is switched off, is listed as
      // nothing rather than as a realm the console would then fail to open.
      if (!realm || realm.enabled === false) continue;
      const decision = await this.effectivePermissionsIn(homeRealmId, subjectId, audience, realmId);
      if (decision.permissions.length === 0 && realmId !== homeRealmId) continue;
      resolved.push({
        realmId,
        name: realm.name,
        displayName: realm.displayName ?? realm.name,
        home: realmId === homeRealmId,
        roles: decision.roles,
        permissions: decision.permissions,
      });
    }
    return resolved;
  }
}
