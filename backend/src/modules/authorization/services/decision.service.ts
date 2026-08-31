import { Db } from 'mongodb';
import {
  ROLE_COLLECTION, ROLE_ASSIGNMENT_COLLECTION, RESOURCE_SERVER_COLLECTION,
} from '../../../shared/models/collections';
import {
  RoleRecord, RoleAssignmentRecord, ResourceServerRecord, EffectivePermission, permissionKey,
} from '../models/authorization.model';

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
 */
export class DecisionService {
  constructor(private readonly db: Db) {}

  /**
   * Live assignments for a subject.
   *
   * Expiry is judged here rather than left to the sweep: a time-bound elevation must stop granting
   * the moment it lapses, not whenever the database next removes it.
   */
  private async liveAssignments(realmId: string, subjectId: string): Promise<RoleAssignmentRecord[]> {
    const now = new Date();
    const held = await this.db
      .collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION)
      .find({ realmId, subjectId }, { projection: { _id: 0 } })
      .toArray();
    return held.filter((assignment) => {
      if (assignment.notBefore && Date.parse(assignment.notBefore) > now.getTime()) return false;
      if (assignment.expiresAt && Date.parse(assignment.expiresAt) <= now.getTime()) return false;
      return true;
    });
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
    const server = await this.db
      .collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION)
      .findOne({ realmId, audience }, { projection: { _id: 0, resourceServerId: 1 } });

    const assignments = await this.liveAssignments(realmId, subjectId);
    const roles = await this.resolveRoles(realmId, assignments.map((assignment) => assignment.roleId));

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
    const { permissions, roles } = await this.effectivePermissions(realmId, subjectId, audience);
    const held = permissions.some(
      (permission) => permission.resource === resource && permission.action === action,
    );
    // Default deny, and the reason names what was missing rather than saying no: a decision a log
    // cannot explain is not auditable.
    return held
      ? { effect: 'allow', reason: `granted by ${roles.join(', ') || 'an assignment'}` }
      : { effect: 'deny', reason: `no role held by this principal grants ${resource}:${action}` };
  }
}
