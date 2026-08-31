import { IdentityRecord, toScimEmails } from '../models/identity.model';

/**
 * SCIM 2.0 projection, in and out.
 *
 * The value of speaking SCIM is that an organisation's existing provisioning tooling works against
 * this authority with no bespoke integration written on either side. That only holds if the document
 * really is SCIM: a nearly-SCIM API is worse than none, because the tooling connects, appears to
 * work, and fails on the attribute nobody tested.
 *
 * The schema extension is where agents, applications and service identities live. They are principals
 * with a lifecycle exactly as people are, and a provisioning system that can create a person but not
 * a service identity is the reason service accounts get created by hand and never deprovisioned.
 */

export const SCIM_USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
export const SCIM_LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
export const SCIM_PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
export const SCIM_ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';

/** The extension. A namespaced URN rather than loose extra fields, so a client can negotiate it. */
export const SCIM_PRINCIPAL_EXTENSION = 'urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal';

export interface ScimUser {
  schemas: string[];
  id: string;
  externalId?: string;
  userName: string;
  name?: { formatted?: string; givenName?: string; familyName?: string };
  emails?: Array<{ value: string; primary?: boolean; type?: string }>;
  active: boolean;
  meta: {
    resourceType: 'User';
    created?: string;
    lastModified?: string;
    location: string;
    version?: string;
  };
  [extension: string]: unknown;
}

/**
 * A principal as SCIM sees it.
 *
 * `active` is the SCIM word and this authority has two fields behind it: whether the principal is
 * usable, and where it stands in its lifecycle. SCIM only has the boolean, so the boolean is what is
 * projected, and the richer state travels in the extension rather than being flattened away.
 */
export function toScimUser(identity: IdentityRecord, baseUrl: string): ScimUser {
  const emails = toScimEmails(identity);
  return {
    schemas: [SCIM_USER_SCHEMA, SCIM_PRINCIPAL_EXTENSION],
    id: identity.subjectId,
    ...(identity.externalId ? { externalId: identity.externalId } : {}),
    userName: identity.userName,
    ...(identity.name ? { name: identity.name } : {}),
    ...(emails.length > 0 ? { emails: emails.map((email, index) => ({ ...email, primary: index === 0 })) } : {}),
    active: identity.active,
    [SCIM_PRINCIPAL_EXTENSION]: {
      // The distinction SCIM's single boolean cannot carry: a suspended principal and a retired one
      // are both inactive and are not the same thing to anyone reviewing them.
      kind: identity.kind,
      lifecycleState: identity.lifecycleState,
      ...(identity.providerId ? { providerId: identity.providerId } : {}),
      // The opaque binding to a consuming application's own record. This authority never resolves it
      // and does not know what it names; publishing it lets an application find its own records for a
      // principal without either side learning the other's vocabulary.
      ...(identity.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
      // Deliberately never the credential, the hash or the session epoch. A provisioning client has
      // no business learning how a principal authenticates.
    },
    meta: {
      resourceType: 'User',
      // Both come from the common metadata every record carries, which is where SCIM expects them.
      ...(identity.meta?.created ? { created: identity.meta.created } : {}),
      ...(identity.meta?.lastModified ? { lastModified: identity.meta.lastModified } : {}),
      location: `${baseUrl}/Users/${identity.subjectId}`,
    },
  };
}

export interface ScimListResponse {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: ScimUser[];
}

export function toScimList(users: ScimUser[], total: number, startIndex: number): ScimListResponse {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: total,
    // One-based, because the specification says so. An off-by-one here is the kind of defect that
    // silently skips a record per page in somebody else's tooling.
    startIndex,
    itemsPerPage: users.length,
    Resources: users,
  };
}

export function scimError(status: number, detail: string, scimType?: string): Record<string, unknown> {
  return {
    schemas: [SCIM_ERROR_SCHEMA],
    status: String(status),
    ...(scimType ? { scimType } : {}),
    detail,
  };
}

/**
 * The subset of SCIM filters worth supporting, and an honest refusal for the rest.
 *
 * The full grammar is large and almost none of it is used: provisioning clients overwhelmingly filter
 * on `userName eq` or `externalId eq`. Supporting those exactly and REFUSING the rest is better than
 * a partial parser that quietly mistranslates a filter it does not really understand, because a
 * mistranslated filter returns the wrong principals rather than an error.
 */
export function parseScimFilter(filter: string | undefined): Record<string, unknown> | { unsupported: string } {
  if (!filter) return {};
  const match = /^\s*(userName|externalId|active)\s+eq\s+"?([^"]*)"?\s*$/i.exec(filter);
  if (!match) return { unsupported: filter };

  const [, attribute, rawValue] = match;
  if (attribute.toLowerCase() === 'active') return { active: rawValue === 'true' };
  return { [attribute]: rawValue };
}

/**
 * Applies a SCIM patch to the fields this authority lets a provisioning client change.
 *
 * An allowlist, and a short one. A provisioning client may correct a name, an email or an external
 * id, and may deactivate a principal. It may not change what a principal can do: authority comes
 * from roles, which are granted here, and letting a directory sync assign them would hand whoever
 * runs that directory the ability to grant themselves anything.
 */
const PATCHABLE = new Set(['username', 'name', 'emails', 'externalid', 'active']);

export function applyScimPatch(
  operations: Array<{ op: string; path?: string; value?: unknown }>,
): Record<string, unknown> | { rejected: string } {
  const update: Record<string, unknown> = {};

  for (const operation of operations) {
    const op = operation.op?.toLowerCase();
    if (op !== 'replace' && op !== 'add') return { rejected: `unsupported operation "${operation.op}"` };

    // A patch with no path replaces the attributes named in its value object.
    const entries = operation.path
      ? [[operation.path, operation.value] as const]
      : Object.entries((operation.value ?? {}) as Record<string, unknown>);

    for (const [path, value] of entries) {
      const attribute = String(path).toLowerCase();
      if (!PATCHABLE.has(attribute)) return { rejected: `"${path}" cannot be changed through provisioning` };

      if (attribute === 'active') update.active = Boolean(value);
      else if (attribute === 'username') update.userName = String(value);
      else if (attribute === 'externalid') update.externalId = String(value);
      else if (attribute === 'name') update.name = value;
      else if (attribute === 'emails') {
        const list = Array.isArray(value) ? value as Array<{ value?: string; primary?: boolean }> : [];
        const primary = list.find((email) => email.primary) ?? list[0];
        if (primary?.value) update.primaryEmail = String(primary.value).toLowerCase();
      }
    }
  }

  return update;
}

/**
 * The lifecycle state a newly provisioned principal lands in.
 *
 * Provisioning must not ACTIVATE. A create says a principal exists; something else says it may
 * operate. A provisioning event that silently grants operational capability is the failure this rule
 * exists to prevent, and it is the one that turns a directory sync into a privilege escalation path.
 */
export function provisionedLifecycleState(autoApprove: boolean): 'active' | 'pending' {
  return autoApprove ? 'active' : 'pending';
}
