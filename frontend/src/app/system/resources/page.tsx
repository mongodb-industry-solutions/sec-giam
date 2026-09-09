'use client';

import { useCallback } from 'react';
import { Boxes } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Fact } from '../../../components/Fact';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { callApi, when } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';

interface CatalogResource {
  resourceId: string;
  name: string;
  actions: string[];
  status: string;
  catalogVersion: number;
}

interface ResourceServer {
  resourceId: string;
  name: string;
  kind: string;
  audience?: string;
  catalogVersion: number;
  validationMode?: string;
  status: string;
  registeredAt?: string;
  resources: CatalogResource[];
}

/**
 * What each resource server has registered: read only, on purpose.
 *
 * Nothing here can be created or changed. A resource server declares its own enforcement points
 * through its own deployment (`PUT /admin/resource-servers/:name/permissions`), because only the
 * code containing a guard can say a permission exists; a role can only ever check one of these
 * already-declared combinations at /system/roles/:roleId, never invent a new one. This page is what
 * answers "where did that come from" for the catalog a role's own matrix already shows in part.
 */
export default function ResourcesPage() {
  const read = useCallback(
    () => callApi<{ resourceServers: ResourceServer[] }>('/resource-servers', { subject: 'the resource server catalog' }),
    [],
  );
  const catalog = useConsoleResource(read, 'The resource server catalog could not be read.');
  const servers = catalog.data?.resourceServers ?? [];

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Boxes}
        title="Resource servers"
        description="Every application, tool or MCP server that has registered what it enforces, and what each currently declares."
      />

      {catalog.error && <ErrorState message={catalog.error} onRetry={() => void catalog.reload()} />}
      {catalog.loading && <LoadingState label="Reading the resource server catalog…" />}

      {!catalog.loading && !catalog.error && servers.length === 0 && (
        <EmptyState
          icon={Boxes}
          title="No resource server registered yet"
          description="Nothing has declared enforcement points in this realm. A role's own permission matrix will offer nothing to grant until one does."
        />
      )}

      {servers.map((server) => (
        <section key={server.resourceId} className="rounded-xl border border-gray-200 bg-white p-5">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="font-semibold text-[#001E2B]">{server.name}</h2>
            <StatusBadge status={server.status} />
            <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
              {server.kind}
            </span>
          </div>

          <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-4">
            <Fact label="Audience" value={server.audience} mono />
            <Fact label="Validation mode" value={server.validationMode} mono />
            <Fact label="Catalog version" value={String(server.catalogVersion)} />
            <Fact label="Registered" value={when(server.registeredAt)} />
          </dl>

          {server.resources.length === 0 ? (
            <p className="mt-3 text-sm text-gray-400">This server declares no resource type.</p>
          ) : (
            <div className="mt-3 overflow-hidden rounded-lg border border-gray-100">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-100 bg-gray-50 text-left">
                    <th scope="col" className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-400">Resource</th>
                    <th scope="col" className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-400">Actions</th>
                    <th scope="col" className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-400">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {server.resources.map((resource) => (
                    <tr key={resource.resourceId} className="border-b border-gray-50 last:border-0">
                      <td className="px-3 py-2 font-medium text-[#001E2B]">{resource.name}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {resource.actions.map((action) => (
                            <span key={action} className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[11px] text-gray-600">
                              {action}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2"><StatusBadge status={resource.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      ))}
    </main>
  );
}
