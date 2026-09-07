'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Plus, Power, ShieldHalf, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { ListToolbar } from '../../../components/ListToolbar';
import { FilterChips } from '../../../components/FilterChips';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { BuiltinBadge, DisabledBadge, Field, INPUT, ScopeBadge } from './parts';
import type { RoleDetail, RoleSummary } from './types';

/**
 * The roles this realm defines, and what each one actually grants.
 *
 * Two counts rather than one, because they answer different questions. What a role STATES is the
 * line an administrator edits; what it grants once its parents are resolved is what a token will
 * carry. A screen showing only the second cannot be used to change anything, and one showing only
 * the first is quietly wrong about every role that inherits.
 */

type ScopeFilter = 'any' | 'self' | 'all';
type StatusFilter = 'any' | 'enabled' | 'disabled';

export default function RolesPage() {
  const [query, setQuery] = useState('');
  const [scope, setScope] = useState<ScopeFilter>('any');
  const [status, setStatus] = useState<StatusFilter>('any');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [creating, setCreating] = useState(false);

  const read = useCallback(
    () => callApi<{ roles: RoleSummary[]; total: number }>('/roles', {
      query: {
        q: query || undefined,
        scopeKind: scope === 'any' ? undefined : scope,
        enabled: status === 'any' ? undefined : String(status === 'enabled'),
        skip: (page - 1) * limit,
        limit,
      },
      subject: 'the roles in this realm',
    }),
    [query, scope, status, page, limit],
  );

  const roles = useConsoleResource(read, 'The roles could not be read.');
  usePermissions();
  const mayManage = can(currentClaims(), 'roles', 'manage');
  const total = roles.data?.total ?? 0;
  const rows = roles.data?.roles ?? [];

  async function toggle(role: RoleSummary) {
    await roles.run(
      role.roleId,
      () => callApi(`/roles/${encodeURIComponent(role.roleId)}`, {
        method: 'PATCH', body: { enabled: !(role.enabled ?? true) }, subject: 'that role',
      }),
      'That role could not be switched.',
    );
  }

  async function create(input: { name: string; displayName: string; description: string; scopeKind: 'self' | 'all' }) {
    const done = await roles.run(
      'new',
      () => callApi<RoleDetail>('/roles', { method: 'POST', body: input, subject: 'that role' }),
      'That role could not be created.',
    );
    if (done) setCreating(false);
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={ShieldHalf}
        title="Roles"
        description="Named permission sets, and what each one grants once its parents are resolved."
        info={
          <>
            A role can only grant permissions a resource server has already registered, so nothing
            defined here grants something no application checks. Roles compose through parents, and
            the effective count is what a token will actually carry.
          </>
        }
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="Define a role" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {creating && (
        <CreateRole onCancel={() => setCreating(false)} onSubmit={create} busy={roles.busy === 'new'} />
      )}

      <ListToolbar
        search={{
          value: query,
          onChange: (next) => { setQuery(next); setPage(1); },
          placeholder: 'Search by name or description',
        }}
        filter={{
          label: 'Filter by scope',
          value: scope,
          onChange: (next) => { setScope(next); setPage(1); },
          options: [
            { key: 'any', label: 'All' },
            { key: 'self', label: 'Own records' },
            { key: 'all', label: 'Realm wide' },
          ],
        }}
        extra={(
          <FilterChips
            label="Filter by status"
            value={status}
            onChange={(next) => { setStatus(next); setPage(1); }}
            options={[
              { key: 'any', label: 'Any status' },
              { key: 'enabled', label: 'Enabled' },
              { key: 'disabled', label: 'Disabled' },
            ]}
          />
        )}
      />

      {roles.error && <ErrorState message={roles.error} onRetry={() => void roles.reload()} />}

      {roles.loading
        ? <LoadingState label="Reading roles…" />
        : rows.length === 0
          ? <EmptyState
              icon={ShieldHalf}
              title={query ? 'No role matches that' : 'This realm defines no roles'}
              description={query
                ? 'Nothing in this realm matches that name or description.'
                : 'A role is what turns a registered permission into something a principal can hold.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {rows.map((role) => (
                  <RecordCard
                    key={role.roleId}
                    title={(
                      <Link href={`/system/roles/${encodeURIComponent(role.roleId)}`} className="hover:underline">
                        {role.displayName}
                      </Link>
                    )}
                    subtitle={role.name}
                    badges={<>
                      <ScopeBadge scopeKind={role.scopeKind} />
                      {role.builtin && <BuiltinBadge />}
                      {!(role.enabled ?? true) && <DisabledBadge />}
                    </>}
                    actions={mayManage && (
                      <Tooltip text={(role.enabled ?? true)
                        ? 'Switches it off. Every assignment survives; it grants nothing, anywhere it is held or inherited from, while it stays this way.'
                        : 'Switches it back on. Every assignment already held resumes granting immediately.'}
                      >
                        <ActionButton
                          icon={Power}
                          label={(role.enabled ?? true) ? 'Disable' : 'Enable'}
                          tone={(role.enabled ?? true) ? 'danger' : 'neutral'}
                          busy={roles.busy === role.roleId}
                          onClick={() => void toggle(role)}
                        />
                      </Tooltip>
                    )}
                    facts={
                      <>
                        <Fact
                          label="Grants"
                          value={role.effectivePermissionCount === role.ownPermissionCount
                            ? `${role.ownPermissionCount} permissions`
                            : `${role.effectivePermissionCount} permissions, ${role.ownPermissionCount} its own`}
                        />
                        <Fact
                          label="Inherits from"
                          value={role.parentRoleIds.length === 0
                            ? 'nothing'
                            : `${role.parentRoleIds.length} role${role.parentRoleIds.length === 1 ? '' : 's'}`}
                        />
                        <Fact label="Held by" value={`${role.assignmentCount} principal${role.assignmentCount === 1 ? '' : 's'}`} />
                      </>
                    }
                  >
                    {role.description && <p className="mt-2 text-sm text-gray-600">{role.description}</p>}
                  </RecordCard>
                ))}
              </ul>

              <Pagination
                page={page}
                totalPages={Math.max(1, Math.ceil(total / limit))}
                total={total}
                limit={limit}
                noun="roles"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}

/**
 * A new role starts empty.
 *
 * Its permissions and its parents are chosen on the role itself, against the catalog the realm's
 * resource servers registered. Offering a permission picker before the role exists would mean
 * building the same control twice and keeping the two in step.
 */
function CreateRole({ onCancel, onSubmit, busy }: {
  onCancel: () => void;
  onSubmit: (input: { name: string; displayName: string; description: string; scopeKind: 'self' | 'all' }) => void;
  busy: boolean;
}) {
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [scopeKind, setScopeKind] = useState<'self' | 'all'>('self');

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ name, displayName: displayName || name, description, scopeKind });
      }}
      className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">Define a role</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Letters, digits, dot, dash and underscore. What applications name.">
          <input required value={name} onChange={(e) => setName(e.target.value)} pattern="[a-zA-Z0-9._-]+" className={INPUT} />
        </Field>
        <Field label="Display name" hint="What a person reads. Defaults to the name.">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
        </Field>
      </div>

      <Field label="Description" hint="Why this role exists, for whoever reviews it later.">
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className={INPUT} />
      </Field>

      <Field label="Scope" hint="Whether the holder reaches only their own records, or the whole realm.">
        <select value={scopeKind} onChange={(e) => setScopeKind(e.target.value as 'self' | 'all')} className={INPUT}>
          <option value="self">Own records only</option>
          <option value="all">Realm wide</option>
        </select>
      </Field>

      <button
        type="submit"
        disabled={busy || !name}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
      >
        <Plus size={12} aria-hidden />
        {busy ? 'Creating…' : 'Create role'}
      </button>
    </form>
  );
}
