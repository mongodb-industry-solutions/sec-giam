'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Boxes, Plus } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Pagination } from '../../../components/Pagination';
import { ListToolbar } from '../../../components/ListToolbar';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { callApi, can, currentClaims } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { ServerForm } from './ServerForm';
import { type ResourceServerResponse, type ServerDraft, draftToRegisterBody, emptyServerDraft } from './shared';

type StatusFilter = 'all' | 'active' | 'deprecated' | 'withdrawn';

/**
 * Every resource server this realm has registered, one compact row each: name, status, audience,
 * how many resource types it declares. "Register a resource server" is a decision made here; editing
 * an existing one is a decision made on ITS OWN screen, not inline in a list row — the same split
 * every other list in this console already makes (a role, a policy, a domain are all "view more" away
 * from their own edit form, never expanded in place), so a list stays scannable regardless of how much
 * a single server declares.
 *
 * "Declares itself" still holds: nothing here can grant a role anything that is not first declared
 * as a resource server's own catalog, exactly the constraint `resource.controller.ts`'s own docstring
 * states. What changed is WHO may do the declaring — a signed-in operator with `permissions:manage`,
 * not only an admin-token deployment script — via `PUT /realms/:realm/resource-servers/:name/permissions`,
 * the identical write `ResourceAdminService.registerCatalog` also serves at the admin-token path.
 */
export default function ResourcesPage() {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [creating, setCreating] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const claims = currentClaims();
  const mayManage = can(claims, 'permissions', 'manage');

  const read = useCallback(
    () => callApi<{ resourceServers: ResourceServerResponse[]; total: number }>('/resource-servers', {
      query: { q: query || undefined, status: status === 'all' ? undefined : status, skip: (page - 1) * limit, limit },
      subject: 'the resource server catalog',
    }),
    [query, status, page, limit],
  );
  const catalog = useConsoleResource(read, 'The resource server catalog could not be read.');
  const servers = catalog.data?.resourceServers ?? [];
  const total = catalog.data?.total ?? 0;

  async function register(draft: ServerDraft) {
    setNotice(null);
    const done = await catalog.run(
      `register-${draft.name}`,
      () => callApi(`/resource-servers/${encodeURIComponent(draft.name)}/permissions`, {
        method: 'PUT', body: draftToRegisterBody(draft), subject: 'that resource server',
      }),
      'That resource server could not be registered.',
    );
    if (done) { setNotice(`${draft.name}: registered.`); setCreating(false); }
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Boxes}
        title="Resource servers"
        description="Every application, tool or MCP server that has registered what it enforces."
        info={
          <>
            A role can only ever check a `resource:action` combination declared here; it can never
            invent one. Open one to see and edit exactly what it declares.
          </>
        }
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="Register a resource server" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {notice && <p className="rounded-lg border border-emerald-100 bg-emerald-50 px-3 py-2 text-xs text-emerald-700">{notice}</p>}

      {creating && (
        <ServerForm
          title="Register a resource server"
          draft={emptyServerDraft()}
          isNew
          busy={catalog.busy !== null}
          onCancel={() => setCreating(false)}
          onSave={(draft) => void register(draft)}
        />
      )}

      <ListToolbar
        search={{ value: query, onChange: (next) => { setQuery(next); setPage(1); }, placeholder: 'Search by name or audience' }}
        filter={{
          label: 'Filter by status',
          value: status,
          onChange: (next) => { setStatus(next); setPage(1); },
          options: [
            { key: 'all', label: 'All' },
            { key: 'active', label: 'Active' },
            { key: 'deprecated', label: 'Deprecated' },
            { key: 'withdrawn', label: 'Withdrawn' },
          ],
        }}
      />

      {catalog.error && <ErrorState message={catalog.error} onRetry={() => void catalog.reload()} />}
      {catalog.loading && <LoadingState label="Reading the resource server catalog…" />}

      {!catalog.loading && !catalog.error && servers.length === 0 && (
        <EmptyState
          icon={Boxes}
          title={query || status !== 'all' ? 'No resource server matches that' : 'No resource server registered yet'}
          description={query || status !== 'all'
            ? 'Nothing in this realm matches that filter.'
            : 'Nothing has declared enforcement points in this realm. A role\'s own permission matrix will offer nothing to grant until one does.'}
        />
      )}

      {servers.length > 0 && (
        <ul className="space-y-3">
          {servers.map((server) => (
            <RecordCard
              key={server.resourceId}
              title={<Link href={`/system/resources/${encodeURIComponent(server.resourceId)}`} className="hover:underline">{server.displayName ?? server.name}</Link>}
              subtitle={server.displayName ? `${server.name} · ${server.audience}` : server.audience}
              badges={<StatusBadge status={server.status} />}
              facts={
                <>
                  <Fact label="Validation mode" value={server.validationMode ?? 'hybrid'} />
                  <Fact
                    label="Resource types"
                    value={`${server.resources.length} declared`}
                  />
                  <Fact label="Catalog version" value={String(server.catalogVersion)} />
                </>
              }
            >
              {server.description && <p className="mt-2 text-xs text-gray-500">{server.description}</p>}
            </RecordCard>
          ))}
        </ul>
      )}

      {!catalog.loading && servers.length > 0 && (
        <Pagination
          page={page}
          totalPages={Math.max(1, Math.ceil(total / limit))}
          total={total}
          limit={limit}
          noun="resource servers"
          onPageChange={setPage}
          onLimitChange={(next) => { setLimit(next); setPage(1); }}
        />
      )}
    </main>
  );
}
