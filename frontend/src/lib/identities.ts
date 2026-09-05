'use client';

/**
 * The principal directory, as the console sees it.
 *
 * The screens speak SCIM directly rather than through a house shape, because the whole value of the
 * authority speaking SCIM is that the document really is SCIM. A nearly-SCIM projection in the middle
 * would be the one place a reader could not check that.
 */

export const SCIM_PRINCIPAL_EXTENSION = 'urn:mongodb:params:scim:schemas:extension:principal:2.0:Principal';

export interface ScimUser {
  schemas: string[];
  id: string;
  externalId?: string;
  userName: string;
  name?: { formatted?: string; givenName?: string; familyName?: string };
  emails?: Array<{ value: string; primary?: boolean; type?: string }>;
  active: boolean;
  meta?: { created?: string; lastModified?: string; location?: string };
  [extension: string]: unknown;
}

export interface ScimList {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: ScimUser[];
}

export interface PrincipalExtension {
  kind?: string;
  lifecycleState?: string;
  domainId?: string;
  accountHolderRef?: string;
}

/** The richer lifecycle SCIM's single boolean cannot carry. Absent when the server did not send it. */
export function extensionOf(user: ScimUser | null): PrincipalExtension {
  return (user?.[SCIM_PRINCIPAL_EXTENSION] as PrincipalExtension | undefined) ?? {};
}

export function primaryEmail(user: ScimUser): string {
  const emails = user.emails ?? [];
  return (emails.find((email) => email.primary) ?? emails[0])?.value ?? '';
}

/**
 * The filters this authority supports, and only those.
 *
 * It refuses anything else rather than half-interpreting it, because a mistranslated filter returns
 * the wrong principals instead of an error. The console offers exactly what will be accepted.
 */
export type FilterAttribute = 'none' | 'userName' | 'externalId' | 'active';

export function scimFilter(attribute: FilterAttribute, value: string): string | undefined {
  if (attribute === 'none' || !value) return undefined;
  return `${attribute} eq "${value}"`;
}
