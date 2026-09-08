'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Globe, Plus, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { ListToolbar } from '../../../components/ListToolbar';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { Field, INPUT } from '../roles/parts';

/**
 * The authentication paths of this realm, and adding one.
 *
 * A domain IS an authentication provider in this model (`domainId`), so this is a `providers`
 * permission, not a new one invented to describe the same thing. The backend has carried full CRUD
 * for it since v41; this page is the part that was never built to reach it.
 */

interface Domain {
  domainId: string;
  name: string;
  displayName: string;
  protocol: string;
  adapter: string;
  enabled: boolean;
  hasClientSecret: boolean;
  registration?: { selfServiceEnabled: boolean; autoApprove: boolean };
  createdAt?: string;
  lastModifiedAt?: string;
}

type Filter = 'all' | 'enabled' | 'disabled';

export default function DomainsPage() {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [creating, setCreating] = useState(false);

  usePermissions();
  const mayManage = can(currentClaims(), 'providers', 'manage');

  const read = useCallback(
    () => callApi<{ items: Domain[]; total: number }>('/domains', {
      query: { q: query || undefined, page, limit },
      subject: 'the authentication paths of this realm',
    }),
    [query, page, limit],
  );
  const domains = useConsoleResource(read, 'The authentication paths could not be read.');

  const total = domains.data?.total ?? 0;
  const allRows = domains.data?.items ?? [];
  const rows = filter === 'all' ? allRows : allRows.filter((row) => row.enabled === (filter === 'enabled'));

  async function create(input: { name: string; displayName: string; protocol: string }) {
    const done = await domains.run(
      'new',
      () => callApi<Domain>('/domains', { method: 'POST', body: input, subject: 'that authentication path' }),
      'That authentication path could not be created.',
    );
    if (done) setCreating(false);
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Globe}
        title="Domains"
        description="Every authentication path a person can prove who they are through in this realm."
        info="A path is created disabled, so nobody signs in through it before its settings have been checked. The last enabled path in a realm cannot be disabled or deleted: that would lock out everybody, including whoever would undo it."
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="Add an authentication path" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {creating && <CreateDomain onCancel={() => setCreating(false)} onSubmit={create} busy={domains.busy === 'new'} />}

      <ListToolbar
        search={{ value: query, onChange: (next) => { setQuery(next); setPage(1); }, placeholder: 'Name or display name' }}
        filter={{
          label: 'Filter by state',
          value: filter,
          onChange: setFilter,
          options: [{ key: 'all', label: 'All' }, { key: 'enabled', label: 'Enabled' }, { key: 'disabled', label: 'Disabled' }],
        }}
      />

      {domains.error && <ErrorState message={domains.error} onRetry={() => void domains.reload()} />}

      {domains.loading
        ? <LoadingState label="Reading the authentication paths…" />
        : rows.length === 0
          ? <EmptyState
              icon={Globe}
              title={query ? 'No path matches that' : 'This realm defines no authentication path'}
              description={query ? 'Nothing matches that name.' : 'Every realm needs at least one way in.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {rows.map((domain) => (
                  <RecordCard
                    key={domain.domainId}
                    title={(
                      <Link href={`/system/domains/${encodeURIComponent(domain.domainId)}`} className="hover:underline">
                        {domain.displayName}
                      </Link>
                    )}
                    subtitle={domain.name}
                    badges={(
                      <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                        domain.enabled ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-gray-200 bg-gray-50 text-gray-500'
                      }`}>
                        {domain.enabled ? 'enabled' : 'disabled'}
                      </span>
                    )}
                    facts={
                      <>
                        <Fact label="Protocol" value={domain.protocol} />
                        <Fact label="Adapter" value={domain.adapter} />
                        <Fact
                          label="Self-registration"
                          value={domain.registration?.selfServiceEnabled
                            ? (domain.registration.autoApprove ? 'open, auto-approved' : 'open, needs approval')
                            : 'closed'}
                        />
                      </>
                    }
                  />
                ))}
              </ul>

              <Pagination
                page={page}
                totalPages={Math.max(1, Math.ceil(total / limit))}
                total={total}
                limit={limit}
                noun="authentication paths"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}

function CreateDomain({ onCancel, onSubmit, busy }: {
  onCancel: () => void;
  onSubmit: (input: { name: string; displayName: string; protocol: string }) => void;
  busy: boolean;
}) {
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [protocol, setProtocol] = useState('internal');

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); onSubmit({ name, displayName: displayName || name, protocol }); }}
      className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">Add an authentication path</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Slug, unique in this realm. What a sign-in screen resolves on.">
          <input required value={name} onChange={(e) => setName(e.target.value)} pattern="[a-zA-Z0-9._-]+" className={INPUT} />
        </Field>
        <Field label="Display name" hint="What a person reads. Defaults to the name.">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
        </Field>
      </div>

      <Field label="Protocol">
        <select value={protocol} onChange={(e) => setProtocol(e.target.value)} className={INPUT}>
          <option value="internal">Internal (local passwords)</option>
          <option value="oidc">OpenID Connect</option>
          <option value="saml">SAML</option>
          <option value="ldap">LDAP</option>
          <option value="spiffe">SPIFFE</option>
        </select>
      </Field>

      <button
        type="submit"
        disabled={busy || !name}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
      >
        <Plus size={12} aria-hidden />
        {busy ? 'Creating…' : 'Create, disabled'}
      </button>
    </form>
  );
}
