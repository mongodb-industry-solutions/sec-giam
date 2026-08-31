import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * The authorization model: what a protected application declares, and what the authority grants.
 *
 * The split is the whole point. A resource server ships its enforcement points in ITS OWN code,
 * because only the code that enforces a permission can say the permission exists. The authority
 * assigns those permissions to roles and roles to principals, because only the authority can say who
 * holds what. Neither side can invent the other's half, and an application stores no assignment.
 */

/** A protected application, registering itself and the audience its tokens carry. */
export interface ResourceServerRecord extends Scoped {
  resourceServerId: string;
  name: string;
  /** What a token must name in `aud` to be accepted here. */
  audience: string;
  /** Bumped by the application when its catalog changes, so drift is visible rather than silent. */
  permissionCatalogVersion: string;
  /**
   * How this application verifies a token.
   *
   * Local verification against the published key set costs nothing per request and keeps the
   * application serving when the authority is unreachable. Introspection is authoritative about
   * revocation and current status. Neither is right in general, so the choice belongs to the
   * resource server, per operation.
   */
  validationMode: 'local-jwks' | 'introspection' | 'hybrid';
  registeredAt: string;
  meta: Meta;
}

/**
 * One enforcement point.
 *
 * The catalog is STATIC and ships with the application, so no permission exists without a guard
 * behind it. A permission the authority could invent would be one nothing checks.
 */
export interface PermissionRecord extends Scoped {
  permissionId: string;
  resourceServerId: string;
  resource: string;
  action: string;
  description: string;
  /** Kept rather than deleted when an application retires one, so existing grants stay explicable. */
  deprecated?: boolean;
  meta: Meta;
}

/** A permission a role holds, named by the resource server that defined it. */
export interface RolePermission {
  resourceServerId: string;
  resource: string;
  action: string;
}

/**
 * Why a role does NOT hold something.
 *
 * Recorded as data rather than left as a comment in the code that seeds it. These are the
 * separation-of-duties findings the platform's role matrix was built around, and an auditor asking
 * "why can this role not read the audit stream" deserves an answer from the system rather than from
 * a source file. An absence with no recorded reason is indistinguishable from an oversight.
 */
export interface DenialRationale {
  resource: string;
  action?: string;
  reason: string;
}

export interface RoleRecord extends Scoped {
  roleId: string;
  name: string;
  displayName: string;
  description: string;
  permissions: RolePermission[];
  /**
   * `self` scopes every record to the caller; `all` is global.
   *
   * A property of the ROLE rather than of each permission, because it is the same answer for all of
   * them: a customer viewing transactions means their own, and no permission changes that.
   */
  scopeKind: 'self' | 'all';
  builtin: boolean;
  /** Role composition, resolved transitively. A document store does this without a recursive join. */
  parentRoleIds?: string[];
  /** The separation-of-duties reasoning, carried with the role it constrains. */
  sodRationale?: string;
  denialRationale?: DenialRationale[];
  meta: Meta;
}

/**
 * A principal holding a role.
 *
 * A permanent assignment has no expiry. An elevation has one, and that is the whole difference: the
 * same record type expresses both, so an elevation is auditable, revocable and listable in exactly
 * the way a stateless capability token is not.
 */
export interface RoleAssignmentRecord extends Scoped {
  assignmentId: string;
  subjectId: string;
  roleId: string;
  /** Narrows the assignment to one object, when it is not realm-wide. */
  scope?: { kind: string; ref: string };
  grantedBy?: string;
  grantedAt: string;
  notBefore?: string;
  expiresAt?: string;
  /** True only for a time-bound elevation, so the expiry sweep cannot touch a permanent grant. */
  ephemeral?: boolean;
  justification?: string;
  approvalRef?: string;
  meta: Meta;
}

/** The claim shape a resource server reads. Deliberately small: it travels in every token. */
export interface EffectivePermission {
  resource: string;
  action: string;
}

export function permissionKey(permission: { resource: string; action: string }): string {
  return `${permission.resource}:${permission.action}`;
}
