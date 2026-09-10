'use client';

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import { Boxes, Plus, Save, Trash2, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Fact } from '../../../components/Fact';
import { Pagination } from '../../../components/Pagination';
import { ListToolbar } from '../../../components/ListToolbar';
import { ActionButton } from '../../../components/RecordCard';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { callApi, can, currentClaims, when } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { Field, INPUT } from '../roles/parts';
import {
  type CatalogResourceDraft, type ResourceServerResponse, type ServerDraft,
  draftFromResponse, draftToRegisterBody, emptyServerDraft, serializeDraft,
} from './shared';

type StatusFilter = 'all' | 'active' | 'deprecated' | 'withdrawn';

/**
 * Every resource server this realm has registered, with its own resources and their declared
 * actions, editable directly from the console.
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
  const [editingId, setEditingId] = useState<string | null>(null);
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

  async function register(name: string, draft: ServerDraft, isNew: boolean) {
    setNotice(null);
    const done = await catalog.run(
      `register-${name}`,
      () => callApi(`/resource-servers/${encodeURIComponent(name)}/permissions`, {
        method: 'PUT', body: draftToRegisterBody(draft), subject: 'that resource server',
      }),
      'That resource server could not be registered.',
    );
    if (done) {
      setNotice(`${name}: registered.`);
      if (isNew) setCreating(false); else setEditingId(null);
    }
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Boxes}
        title="Resource servers"
        description="Every application, tool or MCP server that has registered what it enforces, and what each currently declares."
        info={
          <>
            A role can only ever check a `resource:action` combination declared here; it can never
            invent one. Editing a server's catalog from this screen calls the same registration a
            resource server's own deployment would, so a change here is indistinguishable from one
            the application made about itself.
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
          onSave={(draft) => void register(draft.name, draft, true)}
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

      {servers.map((server) => (
        editingId === server.resourceId ? (
          <ServerForm
            key={server.resourceId}
            title={server.name}
            draft={draftFromResponse(server)}
            original={draftFromResponse(server)}
            busy={catalog.busy === `register-${server.name}`}
            onCancel={() => setEditingId(null)}
            onSave={(draft) => void register(server.name, draft, false)}
          />
        ) : (
          <section key={server.resourceId} className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Link href={`/system/resources/${encodeURIComponent(server.resourceId)}`} className="font-semibold text-[#001E2B] hover:underline">
                  {server.name}
                </Link>
                <StatusBadge status={server.status} />
                <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                  api
                </span>
              </div>
              {mayManage && <ActionButton icon={Save} label="Edit" onClick={() => setEditingId(server.resourceId)} />}
            </div>

            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-4">
              <Fact label="Audience" value={server.audience} mono />
              <Fact label="Validation mode" value={server.validationMode} mono />
              <Fact label="Catalog version" value={String(server.catalogVersion)} />
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
                        <td className="px-3 py-2 font-medium text-[#001E2B]">
                          <Link href={`/system/resources/${encodeURIComponent(resource.resourceId)}`} className="hover:underline">
                            {resource.name}
                          </Link>
                        </td>
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
        )
      ))}

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

/**
 * One resource server's catalog, editable. `dirty` is a value comparison against what was loaded
 * (`serializeDraft`), same as the Roles and OAuth-application detail pages: Save enables only once
 * something actually changed, never merely because the screen is "in edit mode".
 */
function ServerForm({ title, draft: initial, original, isNew, busy, onCancel, onSave }: {
  title: string;
  draft: ServerDraft;
  original?: ServerDraft;
  isNew?: boolean;
  busy: boolean;
  onCancel: () => void;
  onSave: (draft: ServerDraft) => void;
}) {
  const [draft, setDraft] = useState(initial);

  const dirty = useMemo(() => isNew || !original || serializeDraft(draft) !== serializeDraft(original), [draft, original, isNew]);

  function updateRow(rowIndex: number, patch: Partial<CatalogResourceDraft>) {
    setDraft((current) => ({
      ...current,
      resources: current.resources.map((row, i) => (i === rowIndex ? { ...row, ...patch } : row)),
    }));
  }

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); onSave(draft); }}
      className="space-y-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">{isNew ? title : `Edit ${title}`}</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Identifies this server everywhere it is referenced. Fixed once registered.">
          <input
            required
            disabled={!isNew}
            value={draft.name}
            onChange={(e) => setDraft((current) => ({ ...current, name: e.target.value }))}
            className={INPUT}
          />
        </Field>
        <Field label="Audience" hint="What a token must name in `aud` to be accepted here.">
          <input
            value={draft.audience}
            onChange={(e) => setDraft((current) => ({ ...current, audience: e.target.value }))}
            placeholder={draft.name}
            className={INPUT}
          />
        </Field>
        <Field label="Validation mode">
          <select
            value={draft.validationMode}
            onChange={(e) => setDraft((current) => ({ ...current, validationMode: e.target.value }))}
            className={INPUT}
          >
            <option value="hybrid">hybrid</option>
            <option value="local-jwks">local-jwks</option>
            <option value="introspection">introspection</option>
          </select>
        </Field>
        <Field label="Catalog version">
          <input
            type="number"
            min={1}
            value={draft.catalogVersion}
            onChange={(e) => setDraft((current) => ({ ...current, catalogVersion: Number(e.target.value) || 1 }))}
            className={INPUT}
          />
        </Field>
      </div>

      <fieldset className="space-y-2">
        <legend className="text-xs font-medium text-gray-600">Resources and their actions</legend>
        {draft.resources.map((row, rowIndex) => (
          <div key={rowIndex} className="flex flex-wrap items-center gap-2">
            <input
              value={row.name}
              onChange={(e) => updateRow(rowIndex, { name: e.target.value })}
              placeholder="resource"
              className="w-40 rounded-lg border border-gray-200 px-2.5 py-1.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
            <input
              value={row.actionsText}
              onChange={(e) => updateRow(rowIndex, { actionsText: e.target.value })}
              placeholder="view, manage"
              className="min-w-48 flex-1 rounded-lg border border-gray-200 px-2.5 py-1.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
            <button
              type="button"
              onClick={() => setDraft((current) => ({ ...current, resources: current.resources.filter((_, i) => i !== rowIndex) }))}
              className="rounded-lg border border-gray-200 p-1.5 text-gray-400 hover:bg-gray-50"
            >
              <Trash2 size={12} aria-hidden />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => setDraft((current) => ({ ...current, resources: [...current.resources, { name: '', actionsText: '' }] }))}
          className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-700"
        >
          <Plus size={11} aria-hidden />
          Add a resource
        </button>
        <p className="text-[11px] text-gray-400">
          Removing a resource or an action here and saving is how it is withdrawn: kept for the
          record rather than deleted, since a role may already grant it.
        </p>
      </fieldset>

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy || !dirty || !draft.name.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Registering…' : 'Register'}
        </button>
        <ActionButton icon={X} label="Cancel" onClick={onCancel} />
      </div>
    </form>
  );
}
