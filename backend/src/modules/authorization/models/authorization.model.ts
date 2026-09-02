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
/**
 * One enforcement point.
 *
 * The catalog is STATIC and ships with the application, so no permission exists without a guard
 * behind it. A permission the authority could invent would be one nothing checks.
 */
/**
 * A permission is a STRING, `resource:action`, and not a record.
 *
 * P5.1 retired the collection. A permission is vocabulary: it appears on a role, on a policy and in
 * a token, and in all three it is the same string, so there is one spelling and nothing to keep in
 * step. The row it used to be added an identifier nobody referenced and a description nothing read.
 *
 * Where the vocabulary comes FROM is `resource.actions[]`: a resource declares its own verbs, and a
 * permission naming a verb the resource never declared is refused at the point somebody wrote it
 * rather than becoming a rule that silently never fires.
 */

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
  /**
   * Full permission strings, `resource:action`.
   *
   * The same spelling a policy uses and a token carries, so nothing has to be converted between
   * the three places a permission appears.
   */
  permissions: string[];
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
/**
 * The claim shape a resource server reads: one string per permission.
 *
 * Deliberately small, because it travels in every token. It was `{resource, action}` per entry,
 * which is two keys and two quoted strings of JSON for something a single string says.
 */
export type EffectivePermission = string;

/** The scope kind that points an assignment at another realm rather than at an application object. */
export const REALM_SCOPE_KIND = 'realm';

/**
 * Whether a role holding held in `homeRealmId` grants anything in `targetRealmId`.
 *
 * Two rules and no third. A realm-scoped holding grants ONLY in the realm it names, so it never
 * widens the home realm; anything else grants only at home, so an unscoped holding never leaks
 * outward. Neither direction is inferred, which is what keeps one realm's authority out of another.
 */
export function holdingAppliesIn(
  holding: { scope?: { kind: string; ref: string } },
  homeRealmId: string,
  targetRealmId: string,
): boolean {
  return holding.scope?.kind === REALM_SCOPE_KIND
    ? holding.scope.ref === targetRealmId
    : homeRealmId === targetRealmId;
}

/** One realm a principal may administer, with what they hold there. */
export interface AdministrableRealm {
  realmId: string;
  name: string;
  displayName: string;
  /** True for the realm that issues this principal's tokens, false for a realm reached by a grant. */
  home: boolean;
  roles: string[];
  permissions: EffectivePermission[];
}
