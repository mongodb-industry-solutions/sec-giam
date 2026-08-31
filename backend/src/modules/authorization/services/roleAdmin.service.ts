import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import {
  ROLE_COLLECTION, ROLE_ASSIGNMENT_COLLECTION, PERMISSION_COLLECTION, RESOURCE_SERVER_COLLECTION,
} from '../../../shared/models/collections';
import {
  RoleRecord, RoleAssignmentRecord, RolePermission, PermissionRecord, ResourceServerRecord,
  permissionKey,
} from '../models/authorization.model';
import { newMeta, touchMeta } from '../../../shared/models/base.model';

/**
 * Administering roles: what they grant, what they inherit, and who holds them.
 *
 * The decision point answers "what may THIS PRINCIPAL do", which is the question on the token path.
 * This answers the two questions an administrator asks instead: what does this ROLE grant once its
 * parents are resolved, and who is holding it. Neither is derivable from the other, and both are
 * read from the same two collections the decision point reads, so there is no second source of truth.
 *
 * Composition is resolved in the database rather than by repeated round trips, and bounded, because
 * an accidental cycle in role composition would otherwise be an unbounded traversal.
 */

/** The same bound the decision point applies, so an administrator sees what a token would carry. */
const MAX_COMPOSITION_DEPTH = 8;

export interface RoleSummary {
  roleId: string;
  name: string;
  displayName: string;
  description: string;
  scopeKind: RoleRecord['scopeKind'];
  builtin: boolean;
  parentRoleIds: string[];
  /** Permissions written on the role itself, before composition. */
  ownPermissionCount: number;
  /** Permissions once parents are resolved. Always at least the own count. */
  effectivePermissionCount: number;
  assignmentCount: number;
}

export interface ResolvedPermission {
  resource: string;
  action: string;
  resourceServer: string;
  /** The role the permission actually comes from, so an inherited one names its origin. */
  via: string;
  inherited: boolean;
  /** True when no resource server declares it, so it grants nothing anybody enforces. */
  unenforced: boolean;
}

export interface RoleDetail extends RoleSummary {
  parents: Array<{ roleId: string; name: string; displayName: string }>;
  ownPermissions: ResolvedPermission[];
  effectivePermissions: ResolvedPermission[];
  sodRationale?: string;
  denialRationale?: RoleRecord['denialRationale'];
  created?: string;
  lastModified?: string;
}

export interface AssignmentView {
  assignmentId: string;
  subjectId: string;
  roleId: string;
  grantedAt: string;
  grantedBy?: string;
  notBefore?: string;
  expiresAt?: string;
  ephemeral?: boolean;
  justification?: string;
  /** False once an expiry has passed or a start has not arrived. Judged here, not by the sweep. */
  live: boolean;
}

export type RoleRefusal = { status: number; title: string; detail: string };

export function isRoleRefusal(value: unknown): value is RoleRefusal {
  return typeof value === 'object' && value !== null && 'status' in value && 'title' in value;
}

export class RoleAdminService {
  constructor(private readonly db: Db) {}

  private get roles() {
    return this.db.collection<RoleRecord>(ROLE_COLLECTION);
  }

  private get assignments() {
    return this.db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);
  }

  /** Resource server ids to names, so a permission reads as text rather than as an identifier. */
  private async serverNames(realmId: string): Promise<Map<string, string>> {
    const servers = await this.db
      .collection<ResourceServerRecord>(RESOURCE_SERVER_COLLECTION)
      .find({ realmId }, { projection: { _id: 0, resourceServerId: 1, name: 1 } })
      .toArray();
    return new Map(servers.map((server) => [server.resourceServerId, server.name]));
  }

  /** Every permission a resource server in this realm has actually declared. */
  private async declared(realmId: string): Promise<Set<string>> {
    const permissions = await this.db
      .collection<PermissionRecord>(PERMISSION_COLLECTION)
      .find({ realmId, deprecated: { $ne: true } }, { projection: { _id: 0, resource: 1, action: 1 } })
      .toArray();
    return new Set(permissions.map((permission) => permissionKey(permission)));
  }

  private async countAssignments(realmId: string, roleIds: string[]): Promise<Map<string, number>> {
    if (roleIds.length === 0) return new Map();
    const counts = await this.assignments.aggregate<{ _id: string; total: number }>([
      { $match: { realmId, roleId: { $in: roleIds } } },
      { $group: { _id: '$roleId', total: { $sum: 1 } } },
    ]).toArray();
    return new Map(counts.map((entry) => [entry._id, entry.total]));
  }

  /**
   * One role with everything it inherits, in a single traversal.
   *
   * Kept here rather than in the decision point because the shape wanted differs: the token path
   * needs a flat permission list for one audience, an administrator needs to see WHICH role each
   * permission arrived through. Collapsing the two would make one of them lie.
   */
  private async composed(realmId: string, roleId: string): Promise<{ role: RoleRecord; inherited: RoleRecord[] } | null> {
    const [found] = await this.roles.aggregate<RoleRecord & { inherited?: RoleRecord[] }>([
      { $match: { realmId, roleId } },
      {
        $graphLookup: {
          from: ROLE_COLLECTION,
          startWith: '$parentRoleIds',
          connectFromField: 'parentRoleIds',
          connectToField: 'roleId',
          as: 'inherited',
          maxDepth: MAX_COMPOSITION_DEPTH,
        },
      },
      { $project: { _id: 0 } },
    ]).toArray();
    if (!found) return null;
    const { inherited = [], ...role } = found;
    // A cycle would put the role in its own inheritance. Dropped rather than reported as inherited
    // from itself, which reads as a data error to somebody who did not write the cycle.
    return { role: role as RoleRecord, inherited: inherited.filter((parent) => parent.roleId !== roleId) };
  }

  async list(
    realmId: string,
    options: { q?: string; skip?: number; limit?: number } = {},
  ): Promise<{ roles: RoleSummary[]; total: number }> {
    const filter: Record<string, unknown> = { realmId };
    if (options.q) {
      const escaped = options.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = ['name', 'displayName', 'description']
        .map((field) => ({ [field]: { $regex: escaped, $options: 'i' } }));
    }

    const [page, total] = await Promise.all([
      this.roles
        .find(filter, { projection: { _id: 0 } })
        .sort({ name: 1 })
        .skip(Math.max(0, options.skip ?? 0))
        .limit(Math.min(options.limit ?? 20, 200))
        .toArray(),
      this.roles.countDocuments(filter),
    ]);

    const counts = await this.countAssignments(realmId, page.map((role) => role.roleId));

    // Effective counts need the parents, and the parents of a page are a small set: one extra read
    // for the whole page rather than one traversal per row.
    const everyRole = await this.roles
      .find({ realmId }, { projection: { _id: 0, roleId: 1, permissions: 1, parentRoleIds: 1 } })
      .toArray();
    const byId = new Map(everyRole.map((role) => [role.roleId, role]));

    const effectiveCount = (roleId: string): number => {
      const seen = new Set<string>();
      const keys = new Set<string>();
      const walk = (id: string, depth: number) => {
        if (depth > MAX_COMPOSITION_DEPTH || seen.has(id)) return;
        seen.add(id);
        const role = byId.get(id);
        if (!role) return;
        for (const permission of role.permissions ?? []) keys.add(permissionKey(permission));
        for (const parent of role.parentRoleIds ?? []) walk(parent, depth + 1);
      };
      walk(roleId, 0);
      return keys.size;
    };

    return {
      roles: page.map((role) => ({
        roleId: role.roleId,
        name: role.name,
        displayName: role.displayName,
        description: role.description,
        scopeKind: role.scopeKind,
        builtin: role.builtin,
        parentRoleIds: role.parentRoleIds ?? [],
        ownPermissionCount: (role.permissions ?? []).length,
        effectivePermissionCount: effectiveCount(role.roleId),
        assignmentCount: counts.get(role.roleId) ?? 0,
      })),
      total,
    };
  }

  async detail(realmId: string, roleId: string): Promise<RoleDetail | null> {
    const composed = await this.composed(realmId, roleId);
    if (!composed) return null;

    const [names, declared, counts] = await Promise.all([
      this.serverNames(realmId),
      this.declared(realmId),
      this.countAssignments(realmId, [roleId]),
    ]);

    const { role, inherited } = composed;
    const describe = (permission: RolePermission, via: RoleRecord): ResolvedPermission => ({
      resource: permission.resource,
      action: permission.action,
      resourceServer: names.get(permission.resourceServerId) ?? permission.resourceServerId,
      via: via.name,
      inherited: via.roleId !== roleId,
      // A permission no resource server declares is enforceable by nothing, which is worth showing
      // rather than leaving as a row that looks exactly like one that works.
      unenforced: !declared.has(permissionKey(permission)),
    });

    const own = (role.permissions ?? []).map((permission) => describe(permission, role));

    const effective = new Map<string, ResolvedPermission>();
    for (const permission of own) effective.set(`${permission.resource}:${permission.action}`, permission);
    for (const parent of inherited) {
      for (const permission of parent.permissions ?? []) {
        const key = permissionKey(permission);
        // The role's own statement wins the attribution: a permission it holds directly is not
        // inherited, whatever a parent also happens to grant.
        if (!effective.has(key)) effective.set(key, describe(permission, parent));
      }
    }

    const ordered = (list: ResolvedPermission[]) => [...list].sort(
      (a, b) => a.resource.localeCompare(b.resource) || a.action.localeCompare(b.action),
    );

    return {
      roleId: role.roleId,
      name: role.name,
      displayName: role.displayName,
      description: role.description,
      scopeKind: role.scopeKind,
      builtin: role.builtin,
      parentRoleIds: role.parentRoleIds ?? [],
      parents: inherited
        .filter((parent) => (role.parentRoleIds ?? []).includes(parent.roleId))
        .map((parent) => ({ roleId: parent.roleId, name: parent.name, displayName: parent.displayName })),
      ownPermissionCount: own.length,
      effectivePermissionCount: effective.size,
      assignmentCount: counts.get(roleId) ?? 0,
      ownPermissions: ordered(own),
      effectivePermissions: ordered([...effective.values()]),
      ...(role.sodRationale ? { sodRationale: role.sodRationale } : {}),
      ...(role.denialRationale ? { denialRationale: role.denialRationale } : {}),
      ...(role.meta?.created ? { created: role.meta.created } : {}),
      ...(role.meta?.lastModified ? { lastModified: role.meta.lastModified } : {}),
    };
  }

  /**
   * Turns `resource:action` pairs into permissions bound to the resource server that declared them.
   *
   * A pair no server declares is refused rather than stored: the authority may only grant what an
   * application said it enforces, and a role granting something nothing checks is a role that
   * appears to work and does not.
   */
  private async bind(
    realmId: string,
    wanted: Array<{ resource: string; action: string }>,
  ): Promise<RolePermission[] | RoleRefusal> {
    if (wanted.length === 0) return [];
    const declared = await this.db
      .collection<PermissionRecord>(PERMISSION_COLLECTION)
      .find({ realmId }, { projection: { _id: 0, resourceServerId: 1, resource: 1, action: 1 } })
      .toArray();
    const byKey = new Map(declared.map((permission) => [permissionKey(permission), permission]));

    const bound: RolePermission[] = [];
    const unknown: string[] = [];
    for (const permission of wanted) {
      const match = byKey.get(permissionKey(permission));
      if (!match) {
        unknown.push(permissionKey(permission));
        continue;
      }
      bound.push({ resourceServerId: match.resourceServerId, resource: match.resource, action: match.action });
    }
    if (unknown.length > 0) {
      return {
        status: 400,
        title: 'Undeclared permission',
        detail:
          `No resource server in this realm declares ${unknown.join(', ')}. A permission exists only `
          + 'once the application that enforces it has registered its catalog.',
      };
    }
    return bound;
  }

  /** Refuses a parent that does not exist, or one that would close a cycle. */
  private async validParents(
    realmId: string,
    roleId: string,
    parentRoleIds: string[],
  ): Promise<RoleRefusal | null> {
    if (parentRoleIds.length === 0) return null;
    const found = await this.roles
      .find({ realmId, roleId: { $in: parentRoleIds } }, { projection: { _id: 0, roleId: 1 } })
      .toArray();
    const known = new Set(found.map((role) => role.roleId));
    const missing = parentRoleIds.filter((id) => !known.has(id));
    if (missing.length > 0) {
      return { status: 400, title: 'Unknown parent role', detail: `No role in this realm has id ${missing.join(', ')}.` };
    }
    if (parentRoleIds.includes(roleId)) {
      return { status: 409, title: 'Cycle in role composition', detail: 'A role cannot inherit from itself.' };
    }

    // Everything the proposed parents already inherit. If this role is in there, the edge closes a
    // loop, and a loop is not something the traversal bound should be left to absorb silently.
    const ancestors = await this.roles.aggregate<{ roleId: string }>([
      { $match: { realmId, roleId: { $in: parentRoleIds } } },
      {
        $graphLookup: {
          from: ROLE_COLLECTION,
          startWith: '$parentRoleIds',
          connectFromField: 'parentRoleIds',
          connectToField: 'roleId',
          as: 'chain',
          maxDepth: MAX_COMPOSITION_DEPTH,
        },
      },
      { $unwind: '$chain' },
      { $project: { _id: 0, roleId: '$chain.roleId' } },
    ]).toArray();
    if (ancestors.some((ancestor) => ancestor.roleId === roleId)) {
      return {
        status: 409,
        title: 'Cycle in role composition',
        detail: 'One of those parents already inherits from this role, so the composition would loop.',
      };
    }
    return null;
  }

  async create(
    realmId: string,
    tenantId: string,
    input: {
      name: string; displayName?: string; description?: string;
      scopeKind?: RoleRecord['scopeKind'];
      permissions?: Array<{ resource: string; action: string }>;
      parentRoleIds?: string[];
      sodRationale?: string;
    },
  ): Promise<RoleDetail | RoleRefusal> {
    const existing = await this.roles.findOne({ realmId, name: input.name }, { projection: { _id: 0, roleId: 1 } });
    if (existing) {
      return { status: 409, title: 'Role already exists', detail: `This realm already has a role named "${input.name}".` };
    }

    const roleId = uuidv4();
    const parents = input.parentRoleIds ?? [];
    const cycle = await this.validParents(realmId, roleId, parents);
    if (cycle) return cycle;

    const bound = await this.bind(realmId, input.permissions ?? []);
    if (isRoleRefusal(bound)) return bound;

    await this.roles.insertOne({
      realmId,
      tenantId,
      roleId,
      name: input.name,
      displayName: input.displayName ?? input.name,
      description: input.description ?? '',
      permissions: bound,
      scopeKind: input.scopeKind ?? 'self',
      // Never true from here. Builtin means "shipped with the deployment", and a role somebody
      // created through the console is by definition not that.
      builtin: false,
      ...(parents.length > 0 ? { parentRoleIds: parents } : {}),
      ...(input.sodRationale ? { sodRationale: input.sodRationale } : {}),
      meta: newMeta('Role'),
    });

    return await this.detail(realmId, roleId) as RoleDetail;
  }

  async update(
    realmId: string,
    roleId: string,
    patch: {
      displayName?: string; description?: string;
      scopeKind?: RoleRecord['scopeKind'];
      permissions?: Array<{ resource: string; action: string }>;
      parentRoleIds?: string[];
      sodRationale?: string;
    },
  ): Promise<RoleDetail | RoleRefusal | null> {
    const role = await this.roles.findOne({ realmId, roleId }, { projection: { _id: 0 } });
    if (!role) return null;

    const changes: Partial<RoleRecord> = {};
    if (patch.displayName !== undefined) changes.displayName = patch.displayName;
    if (patch.description !== undefined) changes.description = patch.description;
    if (patch.scopeKind !== undefined) changes.scopeKind = patch.scopeKind;
    if (patch.sodRationale !== undefined) changes.sodRationale = patch.sodRationale;

    if (patch.parentRoleIds) {
      const cycle = await this.validParents(realmId, roleId, patch.parentRoleIds);
      if (cycle) return cycle;
      changes.parentRoleIds = patch.parentRoleIds;
    }

    if (patch.permissions) {
      const bound = await this.bind(realmId, patch.permissions);
      if (isRoleRefusal(bound)) return bound;
      changes.permissions = bound;
    }

    if (Object.keys(changes).length > 0) {
      await this.roles.updateOne({ realmId, roleId }, { $set: { ...changes, meta: touchMeta(role.meta) } });
    }
    return await this.detail(realmId, roleId);
  }

  /**
   * Removes a role, and refuses when anything still depends on it.
   *
   * Cascading would silently take authority away from everyone holding it, which is a change nobody
   * asked for made at the moment nobody is watching. The refusal names the count, because "in use"
   * without a number is not something an operator can act on.
   */
  async remove(realmId: string, roleId: string): Promise<{ removed: true } | RoleRefusal | null> {
    const role = await this.roles.findOne({ realmId, roleId }, { projection: { _id: 0, builtin: 1, displayName: 1 } });
    if (!role) return null;

    if (role.builtin) {
      return {
        status: 409,
        title: 'Built-in role',
        detail: 'This role ships with the deployment and is recreated by setup, so removing it here would not remove it.',
      };
    }

    const held = await this.assignments.countDocuments({ realmId, roleId });
    if (held > 0) {
      return {
        status: 409,
        title: 'Role is still assigned',
        detail:
          `${held} assignment${held === 1 ? '' : 's'} still hold this role. Revoke them first: removing `
          + 'the role here would take that authority away without anybody deciding to.',
      };
    }

    const children = await this.roles.countDocuments({ realmId, parentRoleIds: roleId });
    if (children > 0) {
      return {
        status: 409,
        title: 'Role is composed into another',
        detail:
          `${children} role${children === 1 ? '' : 's'} inherit from this one. Detach them first, or `
          + 'they would silently stop granting what they inherit.',
      };
    }

    await this.roles.deleteOne({ realmId, roleId });
    return { removed: true };
  }

  private static view(assignment: RoleAssignmentRecord, now = Date.now()): AssignmentView {
    const started = !assignment.notBefore || Date.parse(assignment.notBefore) <= now;
    const unexpired = !assignment.expiresAt || Date.parse(assignment.expiresAt) > now;
    return {
      assignmentId: assignment.assignmentId,
      subjectId: assignment.subjectId,
      roleId: assignment.roleId,
      grantedAt: assignment.grantedAt,
      ...(assignment.grantedBy ? { grantedBy: assignment.grantedBy } : {}),
      ...(assignment.notBefore ? { notBefore: assignment.notBefore } : {}),
      ...(assignment.expiresAt ? { expiresAt: assignment.expiresAt } : {}),
      ...(assignment.ephemeral ? { ephemeral: assignment.ephemeral } : {}),
      ...(assignment.justification ? { justification: assignment.justification } : {}),
      live: started && unexpired,
    };
  }

  /** Who holds a role, lapsed ones included: "who used to have this" is the question after an incident. */
  async assignmentsFor(realmId: string, roleId: string): Promise<AssignmentView[]> {
    const held = await this.assignments
      .find({ realmId, roleId }, { projection: { _id: 0 } })
      .sort({ grantedAt: -1 })
      .toArray();
    const now = Date.now();
    return held.map((assignment) => RoleAdminService.view(assignment, now));
  }

  async grant(
    realmId: string,
    tenantId: string,
    input: { roleId: string; subjectId: string; grantedBy: string; expiresAt?: string; justification?: string },
  ): Promise<AssignmentView | RoleRefusal | null> {
    const role = await this.roles.findOne({ realmId, roleId: input.roleId }, { projection: { _id: 0, roleId: 1 } });
    if (!role) return null;

    const duplicate = await this.assignments.findOne(
      { realmId, roleId: input.roleId, subjectId: input.subjectId },
      { projection: { _id: 0, assignmentId: 1 } },
    );
    if (duplicate) {
      return {
        status: 409,
        title: 'Already assigned',
        detail: 'That principal already holds this role. Revoke the existing assignment to change its terms.',
      };
    }

    const assignment: RoleAssignmentRecord = {
      realmId,
      tenantId,
      assignmentId: uuidv4(),
      subjectId: input.subjectId,
      roleId: input.roleId,
      grantedBy: input.grantedBy,
      grantedAt: new Date().toISOString(),
      // An expiry is what makes this an elevation rather than a standing grant, so the flag follows
      // the expiry rather than being asked for separately and getting out of step with it.
      ...(input.expiresAt ? { expiresAt: input.expiresAt, ephemeral: true } : {}),
      ...(input.justification ? { justification: input.justification } : {}),
      meta: newMeta('RoleAssignment'),
    };
    await this.assignments.insertOne(assignment);
    return RoleAdminService.view(assignment);
  }

  /** Removes one assignment. The role and every other holder are untouched. */
  async revoke(realmId: string, assignmentId: string): Promise<AssignmentView | null> {
    const assignment = await this.assignments.findOne({ realmId, assignmentId }, { projection: { _id: 0 } });
    if (!assignment) return null;
    await this.assignments.deleteOne({ realmId, assignmentId });
    return RoleAdminService.view(assignment);
  }

  /** Every permission any resource server in this realm declares, for building a role. */
  async catalog(realmId: string): Promise<Array<{ resource: string; action: string; description: string; resourceServer: string; deprecated: boolean }>> {
    const [names, permissions] = await Promise.all([
      this.serverNames(realmId),
      this.db.collection<PermissionRecord>(PERMISSION_COLLECTION)
        .find({ realmId }, { projection: { _id: 0 } })
        .sort({ resource: 1, action: 1 })
        .toArray(),
    ]);
    return permissions.map((permission) => ({
      resource: permission.resource,
      action: permission.action,
      description: permission.description,
      resourceServer: names.get(permission.resourceServerId) ?? permission.resourceServerId,
      deprecated: Boolean(permission.deprecated),
    }));
  }
}
