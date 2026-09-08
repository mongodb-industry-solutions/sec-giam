import { Db } from 'mongodb';
import { DecisionService } from './decision.service';
import { permissionString } from '../models/resource.model';

/**
 * What a principal may do to the AUTHORITY'S OWN objects, and how widely.
 *
 * Resolved against the `authority` resource server rather than the audience of the token that
 * happened to arrive, so administering identity is never something a business application's token
 * carries by accident. The permissions are read from the database rather than from the token's
 * claims, which means a role withdrawn a moment ago is withdrawn here without waiting for an expiry.
 *
 * `scopeKind` is the tier. `self` is an ordinary registered user, who reaches their own account and
 * nothing else; `all` is an administrator of the realm. It is a property of the role rather than of
 * each permission because it is the same answer for all of them, and inventing a second mechanism
 * for the same distinction is how the two drift apart.
 */

/** The authority's own resource server, so administering it is a permission like any other. */
export const AUTHORITY_RESOURCE_SERVER = 'authority';

export interface AuthorityAccess {
  roles: string[];
  scopeKind: 'self' | 'all';
  can(resource: string, action: string): boolean;
  /** True when this caller reaches other principals' records at all. */
  readonly realmWide: boolean;
}

export async function authorityAccess(
  db: Db,
  realmId: string,
  subjectId: string,
): Promise<AuthorityAccess> {
  const decision = await new DecisionService(db)
    .effectivePermissions(realmId, subjectId, AUTHORITY_RESOURCE_SERVER);

  return {
    roles: decision.roles,
    scopeKind: decision.scopeKind,
    realmWide: decision.scopeKind === 'all',
    can: (resource, action) => decision.permissions.includes(permissionString(resource, action)),
  };
}

/** The refusal text, naming what was missing rather than saying no. */
export function refusal(resource: string, action: string): string {
  return `No role held by this principal grants ${action} on ${resource}.`;
}
