/**
 * The resource-server draft shape and its pure logic, shared by the admin-token panel
 * (`/admin/panel/resources`) and the RBAC-gated console page (`/system/resources`).
 *
 * Only the DATA logic is shared: how a draft is built from what the server returned, how it is
 * compared against that to decide whether Save should be enabled, and how it is turned back into a
 * request body. The two pages render it with different themes (dark for the ops panel, light for
 * the ordinary console, matching everything else in each), so the JSX itself is not shared, only
 * what decides what the JSX shows.
 */

export interface CatalogResourceDraft {
  resourceId?: string;
  name: string;
  actionsText: string;
}

export interface ServerDraft {
  resourceId?: string;
  name: string;
  audience: string;
  catalogVersion: number;
  validationMode: string;
  status?: string;
  resources: CatalogResourceDraft[];
}

export interface ResourceServerResponse {
  resourceId: string;
  name: string;
  displayName?: string;
  description?: string;
  audience?: string;
  catalogVersion: number;
  validationMode?: string;
  status: string;
  resources: Array<{ resourceId: string; name: string; displayName?: string; description?: string; actions: string[]; status: string }>;
}

export function emptyServerDraft(): ServerDraft {
  return { name: '', audience: '', catalogVersion: 1, validationMode: 'hybrid', resources: [{ name: '', actionsText: '' }] };
}

export function draftFromResponse(server: ResourceServerResponse): ServerDraft {
  return {
    resourceId: server.resourceId,
    name: server.name,
    audience: server.audience ?? '',
    catalogVersion: server.catalogVersion,
    validationMode: server.validationMode ?? 'hybrid',
    status: server.status,
    resources: server.resources.map((resource) => ({
      resourceId: resource.resourceId,
      name: resource.name,
      actionsText: resource.actions.join(', '),
    })),
  };
}

/** A canonical form to compare a draft against what was loaded, so Save enables only once something really changed. */
export function serializeDraft(draft: ServerDraft): string {
  return JSON.stringify({
    audience: draft.audience,
    validationMode: draft.validationMode,
    resources: draft.resources
      .map((r) => ({ name: r.name.trim(), actions: r.actionsText.split(',').map((a) => a.trim()).filter(Boolean).sort() }))
      .filter((r) => r.name)
      .sort((a, b) => a.name.localeCompare(b.name)),
  });
}

/** The body `PUT .../resource-servers/:name/permissions` expects, either auth wrapper. */
export function draftToRegisterBody(draft: ServerDraft) {
  return {
    audience: draft.audience || draft.name,
    catalogVersion: draft.catalogVersion,
    validationMode: draft.validationMode,
    permissions: draft.resources.flatMap((row) => row.actionsText.split(',').map((a) => a.trim()).filter(Boolean)
      .map((action) => ({ resource: row.name.trim(), action }))).filter((p) => p.resource),
  };
}
