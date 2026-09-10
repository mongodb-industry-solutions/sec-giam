'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Plus, Scale, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Pagination } from '../../../components/Pagination';
import { ListToolbar } from '../../../components/ListToolbar';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { Field, INPUT } from '../roles/parts';
import { EffectBadge, ResourceFields, StatusBadge } from './parts';
import type { PolicyDetail, PolicySummary } from './types';

/**
 * The conditional rules this realm applies, evaluated after roles.
 *
 * One policy is one rule since v40: one effect, over one resource pattern, under conditions. Two
 * rules that used to live as two statements in one policy are two policies now, each separately
 * versionable and separately approvable.
 */

type StatusFilter = 'all' | 'active' | 'draft' | 'retired';

export default function PoliciesPage() {
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<StatusFilter>('all');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [creating, setCreating] = useState(false);

  const read = useCallback(
    () => callApi<{ policies: PolicySummary[]; total: number }>('/policies', {
      query: { q: query || undefined, status: status === 'all' ? undefined : status, skip: (page - 1) * limit, limit },
      subject: 'the policies in this realm',
    }),
    [query, status, page, limit],
  );

  const policies = useConsoleResource(read, 'The policies could not be read.');
  usePermissions();
  const mayManage = can(currentClaims(), 'policies', 'manage');
  const total = policies.data?.total ?? 0;
  const rows = policies.data?.policies ?? [];

  async function create(input: {
    name: string; effect: 'allow' | 'deny'; resourceMode: 'names' | 'pattern'; resourceNames: string; resourcePattern: string;
    permissions: string; reason: string;
  }) {
    const done = await policies.run(
      'new',
      () => callApi<PolicyDetail>('/policies', {
        method: 'POST',
        body: {
          name: input.name,
          effect: input.effect,
          resource: input.resourceMode === 'names'
            ? { names: input.resourceNames.split(',').map((value) => value.trim()).filter(Boolean) }
            : { pattern: input.resourcePattern },
          permissions: input.permissions.split(',').map((value) => value.trim()).filter(Boolean),
          ...(input.reason ? { reason: input.reason } : {}),
        },
        subject: 'that policy',
      }),
      'That policy could not be created.',
    );
    if (done) setCreating(false);
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Scale}
        title="Policies"
        description="One rule each, evaluated after roles, where deny always wins."
        info={
          <>
            A policy can only ever narrow what a role granted, never widen it, and a deny anywhere in
            the realm beats every allow everywhere else. Conditions are identity context only:
            assurance, network, time of day, tenant and attestation. Open one and use the simulator to
            see whether it decides a request before trusting that it does.
          </>
        }
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="State a policy" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {creating && (
        <CreatePolicy onCancel={() => setCreating(false)} onSubmit={create} busy={policies.busy === 'new'} />
      )}

      <ListToolbar
        search={{
          value: query,
          onChange: (next) => { setQuery(next); setPage(1); },
          placeholder: 'Search by name',
        }}
        filter={{
          label: 'Filter by status',
          value: status,
          onChange: (next) => { setStatus(next); setPage(1); },
          options: [
            { key: 'all', label: 'All' },
            { key: 'active', label: 'Active' },
            { key: 'draft', label: 'Draft' },
            { key: 'retired', label: 'Retired' },
          ],
        }}
      />

      {policies.error && <ErrorState message={policies.error} onRetry={() => void policies.reload()} />}

      {policies.loading
        ? <LoadingState label="Reading policies…" />
        : rows.length === 0
          ? <EmptyState
              icon={Scale}
              title={query ? 'No policy matches that' : 'This realm states no policies'}
              description={query
                ? 'Nothing in this realm matches that name.'
                : 'Without one, every decision rests on roles alone. A policy is how a realm withholds something a role would otherwise grant.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {rows.map((policy) => (
                  <RecordCard
                    key={policy.policyId}
                    title={(
                      <Link href={`/system/policies/${encodeURIComponent(policy.policyId)}`} className="hover:underline">
                        {policy.name}
                      </Link>
                    )}
                    subtitle={`version ${policy.version}`}
                    badges={
                      <>
                        <EffectBadge effect={policy.effect} />
                        <StatusBadge status={policy.status} />
                      </>
                    }
                    facts={
                      <>
                        <Fact label="Grants" value={`${policy.permissionCount} permission${policy.permissionCount === 1 ? '' : 's'}`} />
                        <Fact
                          label="Conditional"
                          value={policy.conditionCount === 0 ? 'always applies' : `${policy.conditionCount} of them`}
                        />
                        <Fact label="In effect" value={policy.inEffect ? 'yes' : 'no'} />
                        <Fact label="Last changed" value={when(policy.lastModified)} />
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
                noun="policies"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}

/**
 * A new policy is one rule from the start.
 *
 * Conditions are added on the policy's own screen, where the simulator sits beside them. Offering
 * the whole condition vocabulary before the policy exists would mean building that editor twice.
 */
function CreatePolicy({ onCancel, onSubmit, busy }: {
  onCancel: () => void;
  onSubmit: (input: {
    name: string; effect: 'allow' | 'deny'; resourceMode: 'names' | 'pattern'; resourceNames: string; resourcePattern: string;
    permissions: string; reason: string;
  }) => void;
  busy: boolean;
}) {
  const [name, setName] = useState('');
  const [effect, setEffect] = useState<'allow' | 'deny'>('allow');
  const [resourceMode, setResourceMode] = useState<'names' | 'pattern'>('names');
  const [resourceNames, setResourceNames] = useState('');
  const [resourcePattern, setResourcePattern] = useState('');
  const [permissions, setPermissions] = useState('');
  const [reason, setReason] = useState('');

  const resourceGiven = resourceMode === 'names' ? resourceNames.trim() : resourcePattern.trim();

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ name, effect, resourceMode, resourceNames, resourcePattern, permissions, reason });
      }}
      className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">State a policy</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Letters, digits, dot, dash and underscore. It names the policy in every decision record.">
          <input required value={name} onChange={(e) => setName(e.target.value)} pattern="[a-zA-Z0-9._-]+" className={INPUT} />
        </Field>
        <Field label="Effect" hint="Deny wins over every allow, here and everywhere else in the realm.">
          <select value={effect} onChange={(e) => setEffect(e.target.value as 'allow' | 'deny')} className={INPUT}>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </Field>
      </div>

      <ResourceFields
        mode={resourceMode}
        onModeChange={setResourceMode}
        names={resourceNames}
        onNamesChange={setResourceNames}
        pattern={resourcePattern}
        onPatternChange={setResourcePattern}
      />

      <Field label="Permissions" hint="Comma separated, full resource:action strings. The same spelling a role and a token use.">
        <input required value={permissions} onChange={(e) => setPermissions(e.target.value)} className={INPUT} placeholder="roles:manage, sessions:view" />
      </Field>

      <Field label="Reason" hint="Carried into every decision this policy makes. A decision a log cannot explain is not auditable.">
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} className={INPUT} />
      </Field>

      <button
        type="submit"
        disabled={busy || !name || !permissions.trim() || !resourceGiven}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
      >
        <Plus size={12} aria-hidden />
        {busy ? 'Creating…' : 'Create policy'}
      </button>
    </form>
  );
}
