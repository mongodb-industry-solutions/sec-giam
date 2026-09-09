/** The role shapes the authority returns. Mirrors the contract, and nothing is derived on the client. */

export interface RoleSummary {
  roleId: string;
  name: string;
  displayName: string;
  description: string;
  scopeKind: 'self' | 'all';
  builtin: boolean;
  /** Switched off grants nothing, everywhere it is held or inherited from, without touching an assignment. */
  enabled: boolean;
  parentRoleIds: string[];
  /** Permissions written on the role itself, before composition. */
  ownPermissionCount: number;
  /** Permissions once parents are resolved. What a token will actually carry. */
  effectivePermissionCount: number;
  assignmentCount: number;
}

export interface ResolvedPermission {
  resource: string;
  action: string;
  resourceServer: string;
  /** The role it comes from, which differs from this one when it is inherited. */
  via: string;
  inherited: boolean;
  /** No resource server declares it, so nothing enforces it. */
  unenforced: boolean;
}

export interface RoleDetail extends RoleSummary {
  parents: Array<{ roleId: string; name: string; displayName: string }>;
  ownPermissions: ResolvedPermission[];
  effectivePermissions: ResolvedPermission[];
  sodRationale?: string;
  denialRationale?: Array<{ resource: string; action?: string; reason: string }>;
  created?: string;
  lastModified?: string;
}

/**
 * One holding: a subject and a role, nothing more. Matches AssignmentView on the backend exactly,
 * which the DELETE route's own words explain: "a role a subject holds lives on the subject and has
 * no identifier of its own" (role.controller.ts). Addressed by `(subjectId, roleId)`, never by an
 * assignment id, because there isn't one.
 */
export interface Assignment {
  /** The person behind the subject id. Absent when the record carries no name. */
  userName?: string;
  subjectId: string;
  roleId: string;
  grantedAt: string;
  grantedBy?: string;
  expiresAt?: string;
  ephemeral?: boolean;
  justification?: string;
  live: boolean;
}

export interface CatalogPermission {
  resource: string;
  action: string;
  description?: string;
  resourceServer: string;
  deprecated?: boolean;
}
