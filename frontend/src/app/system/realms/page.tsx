'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { Building2, Plus, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, RecordCard } from '../../../components/RecordCard';
import { Fact } from '../../../components/Fact';
import { callApi, can, currentClaims } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { Field, INPUT } from '../roles/parts';

/**
 * Every realm this deployment hosts: its own trust and key boundary.
 *
 * Realm-wide by nature, so seeing more than the caller's own home realm is always an oversight
 * read: the authority narrows the answer to just that one realm rather than refusing outright, the
 * same fallback every other oversight surface in this console already uses.
 */

interface Realm {
  realmId: string;
  name: string;
  displayName: string;
  issuer: string;
  enabled: boolean;
  demoMode: boolean;
}

export default function RealmsPage() {
  const [creating, setCreating] = useState(false);

  const read = useCallback(
    () => callApi<{ realms: Realm[] }>('/realms', { topLevel: true, subject: 'the realms this deployment hosts' }),
    [],
  );
  const realms = useConsoleResource(read, 'The realms could not be read.');
  usePermissions();
  const mayManage = can(currentClaims(), 'realms', 'manage');
  const rows = realms.data?.realms ?? [];

  async function create(input: { name: string; displayName: string }) {
    const done = await realms.run(
      'new',
      () => callApi<Realm>('/realms', { topLevel: true, method: 'POST', body: input, subject: 'that realm' }),
      'That realm could not be created.',
    );
    if (done) setCreating(false);
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Building2}
        title="Realms"
        description="Every trust and key boundary this deployment hosts. A token minted in one is refused by another."
        info={
          <>
            Provisions the realm, its own internal directory and a published signing key together,
            so it can sign somebody in immediately. Only your own home realm is ever shown here
            unless a role reaches beyond it, the same as everywhere else in this console.
          </>
        }
        actions={mayManage && !creating
          ? <ActionButton icon={Plus} label="Provision a realm" tone="primary" onClick={() => setCreating(true)} />
          : undefined}
      />

      {creating && (
        <CreateRealm onCancel={() => setCreating(false)} onSubmit={create} busy={realms.busy === 'new'} />
      )}

      {realms.error && <ErrorState message={realms.error} onRetry={() => void realms.reload()} />}

      {realms.loading
        ? <LoadingState label="Reading realms…" />
        : rows.length === 0
          ? <EmptyState icon={Building2} title="No realm is visible" description="Your own home realm should always appear here. Something is wrong if it does not." />
          : (
            <ul className="space-y-3">
              {rows.map((realm) => (
                <RecordCard
                  key={realm.realmId}
                  title={(
                    <Link href={`/system/realms/${encodeURIComponent(realm.name)}`} className="hover:underline">
                      {realm.displayName}
                    </Link>
                  )}
                  subtitle={realm.name}
                  badges={(
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                      realm.enabled ? 'border-emerald-200 bg-emerald-50 text-emerald-700' : 'border-gray-200 bg-gray-50 text-gray-500'
                    }`}>
                      {realm.enabled ? 'enabled' : 'disabled'}
                    </span>
                  )}
                  facts={
                    <>
                      <Fact label="Issuer" value={realm.issuer} mono />
                      <Fact label="Demo mode" value={realm.demoMode ? 'yes' : 'no'} />
                    </>
                  }
                />
              ))}
            </ul>
          )}
    </main>
  );
}

function CreateRealm({ onCancel, onSubmit, busy }: {
  onCancel: () => void;
  onSubmit: (input: { name: string; displayName: string }) => void;
  busy: boolean;
}) {
  const [name, setName] = useState('');
  const [displayName, setDisplayName] = useState('');

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); onSubmit({ name, displayName: displayName || name }); }}
      className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">Provision a realm</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Lowercase, digits and dashes. Becomes part of the issuer URL and cannot be changed afterwards.">
          <input required value={name} onChange={(e) => setName(e.target.value)} pattern="[a-z0-9][a-z0-9-]*" className={INPUT} />
        </Field>
        <Field label="Display name" hint="What a person reads. Defaults to the name.">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
        </Field>
      </div>

      <Tooltip text="Created enabled, with its own internal directory and a published signing key, ready to sign somebody in right away.">
        <button
          type="submit"
          disabled={busy || !name}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Plus size={12} aria-hidden />
          {busy ? 'Provisioning…' : 'Provision realm'}
        </button>
      </Tooltip>
    </form>
  );
}
