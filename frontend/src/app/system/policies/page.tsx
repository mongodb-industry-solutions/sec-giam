'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Plus, Scale, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { Field, INPUT } from '../roles/parts';
import { DisabledBadge, EffectBadge } from './parts';
import type { PolicyDetail, PolicySummary } from './types';

/**
 * The conditional statements this realm applies, evaluated after roles.
 *
 * The deny count is a column of its own rather than folded into the total, because the two answer
 * different questions. A policy that only permits can be removed and nothing is taken away; one that
 * denies is holding something back, and removing it widens access the moment it goes. A single count
 * makes those look like the same object.
 */

export default function PoliciesPage() {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [creating, setCreating] = useState(false);

  const read = useCallback(
    () => callApi<{ policies: PolicySummary[]; total: number }>('/policies', {
      query: { q: query || undefined, skip: (page - 1) * limit, limit },
      subject: 'the policies in this realm',
    }),
    [query, page, limit],
  );

  const policies = useConsoleResource(read, 'The policies could not be read.');
  usePermissions();
  const mayManage = can(currentClaims(), 'policies', 'manage');
  const total = policies.data?.total ?? 0;
  const rows = policies.data?.policies ?? [];

  async function create(input: { name: string; effect: 'allow' | 'deny'; resources: string; actions: string; reason: string }) {
    const done = await policies.run(
      'new',
      () => callApi<PolicyDetail>('/policies', {
        method: 'POST',
        body: {
          name: input.name,
          version: '1',
          statements: [{
            effect: input.effect,
            ...(input.resources ? { resources: input.resources.split(',').map((value) => value.trim()).filter(Boolean) } : {}),
            ...(input.actions ? { actions: input.actions.split(',').map((value) => value.trim()).filter(Boolean) } : {}),
            ...(input.reason ? { reason: input.reason } : {}),
          }],
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
        description="Conditional statements evaluated after roles, where deny always wins."
        info={
          <>
            A policy can only ever narrow what a role granted, never widen it, and a deny anywhere in
            the realm beats every allow everywhere else. Conditions are identity context only:
            assurance, network, time of day, tenant and attestation. Open one and use the simulator to
            see which statement decides a request before trusting that it does.
          </>
        }
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="State a policy" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {creating && (
        <CreatePolicy onCancel={() => setCreating(false)} onSubmit={create} busy={policies.busy === 'new'} />
      )}

      <label className="block">
        <span className="sr-only">Search policies</span>
        <input
          type="search"
          value={query}
          onChange={(event) => { setQuery(event.target.value); setPage(1); }}
          placeholder="Search by name or version"
          className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 placeholder-gray-400 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      {policies.error && <ErrorState message={policies.error} onRetry={() => void policies.reload()} />}

      {policies.loading
        ? <LoadingState label="Reading policies…" />
        : rows.length === 0
          ? <EmptyState
              icon={Scale}
              title={query ? 'No policy matches that' : 'This realm states no policies'}
              description={query
                ? 'Nothing in this realm matches that name or version.'
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
                        {policy.denyCount > 0 && <EffectBadge effect="deny" />}
                        {policy.denyCount < policy.statementCount && <EffectBadge effect="allow" />}
                        {!policy.enabled && <DisabledBadge />}
                      </>
                    }
                    facts={
                      <>
                        <Fact
                          label="States"
                          value={policy.denyCount === 0
                            ? `${policy.statementCount} statement${policy.statementCount === 1 ? '' : 's'}`
                            : `${policy.statementCount} statement${policy.statementCount === 1 ? '' : 's'}, ${policy.denyCount} prohibiting`}
                        />
                        <Fact
                          label="Conditional"
                          value={policy.conditionCount === 0
                            ? 'always applies'
                            : `${policy.conditionCount} of them`}
                        />
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
 * A new policy starts with one unconditional statement.
 *
 * Conditions are added on the policy itself, where the simulator sits beside them. Offering the
 * whole condition vocabulary before the policy exists would mean building that editor twice and
 * keeping two copies of a closed vocabulary in step, which is how one of them quietly widens.
 */
function CreatePolicy({ onCancel, onSubmit, busy }: {
  onCancel: () => void;
  onSubmit: (input: { name: string; effect: 'allow' | 'deny'; resources: string; actions: string; reason: string }) => void;
  busy: boolean;
}) {
  const [name, setName] = useState('');
  const [effect, setEffect] = useState<'allow' | 'deny'>('allow');
  const [resources, setResources] = useState('');
  const [actions, setActions] = useState('');
  const [reason, setReason] = useState('');

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit({ name, effect, resources, actions, reason });
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

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Resources" hint="Comma separated. Leave empty for anything. A trailing * matches a prefix.">
          <input value={resources} onChange={(e) => setResources(e.target.value)} className={INPUT} placeholder="roles, sessions" />
        </Field>
        <Field label="Actions" hint="Comma separated. Leave empty for anything.">
          <input value={actions} onChange={(e) => setActions(e.target.value)} className={INPUT} placeholder="view, manage" />
        </Field>
      </div>

      <Field label="Reason" hint="Carried into every decision this statement makes. A decision a log cannot explain is not auditable.">
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} className={INPUT} />
      </Field>

      <button
        type="submit"
        disabled={busy || !name}
        className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
      >
        <Plus size={12} aria-hidden />
        {busy ? 'Creating…' : 'Create policy'}
      </button>
    </form>
  );
}
