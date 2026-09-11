'use client';

import { useCallback, useEffect, useState } from 'react';
import { Globe, Plus, Trash2 } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../lib/console';
import { useAdministrableRealms, useRealmChange } from '../../../lib/realms';
import { useConfirm } from '../../../components/ConfirmProvider';

/**
 * Administering more than one realm, and who was allowed to.
 *
 * A principal has one realm: it holds their identity, their credentials and the key that signs their
 * token, and no other realm accepts that token as its own. Administering a second realm is therefore
 * not a second account, it is an assignment held HERE whose scope names the other realm. This screen
 * is both halves of that: which realms the person themselves may act on, and every grant this realm
 * has handed out across the boundary.
 */

interface RealmGrant {
  assignmentId: string;
  subjectId: string;
  roleId: string;
  roleName?: string;
  targetRealm?: string;
  targetRealmId?: string;
  grantedBy?: string;
  grantedAt?: string;
  expiresAt?: string;
  justification?: string;
}

export default function RealmGrantsPage() {
  const confirm = useConfirm();
  const { realms, active, loading: loadingRealms } = useAdministrableRealms();
  const [grants, setGrants] = useState<RealmGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [mayManage, setMayManage] = useState(false);
  const [mayView, setMayView] = useState(false);

  useEffect(() => {
    const claims = currentClaims();
    setMayManage(can(claims, 'assignments', 'manage'));
    setMayView(can(claims, 'assignments', 'view'));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const body = await callApi<{ grants: RealmGrant[] }>('/realm-grants', { subject: 'cross-realm grants' });
      setGrants(body.grants ?? []);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'Cross-realm grants could not be read.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useRealmChange(() => { void load(); });

  async function revoke(grant: RealmGrant) {
    if (!(await confirm(`Take back administration of ${grant.targetRealm ?? 'that realm'}? It stops immediately.`))) return;
    setBusy(grant.assignmentId);
    try {
      await callApi(`/realm-grants/${encodeURIComponent(grant.assignmentId)}`, {
        method: 'DELETE',
        subject: 'that grant',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That grant could not be taken back.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Globe}
        title="Cross-realm administration"
        description="Who administers a realm that is not their own, and what they hold there."
        info="A principal belongs to exactly one realm, which issues and signs their token. Administering a second realm is an assignment held in the first whose scope names the second, so no token is ever accepted by a realm that did not mint it."
      />

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-[#001E2B]">Realms you may act on</h2>
        {loadingRealms
          ? <LoadingState label="Reading the realms you administer…" />
          : (
            <ul className="grid gap-3 sm:grid-cols-2">
              {realms.map((realm) => (
                <li
                  key={realm.realmId}
                  className={`rounded-xl border bg-white p-4 shadow-sm ${
                    realm.name === active ? 'border-[#00ED64] ring-1 ring-[#00ED64]/40' : 'border-gray-200'
                  }`}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-[#001E2B]">{realm.displayName}</span>
                    <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
                      realm.home ? 'border-gray-200 bg-gray-50 text-gray-600' : 'border-amber-200 bg-amber-50 text-amber-700'
                    }`}
                    >
                      {realm.home ? 'your realm' : 'granted'}
                    </span>
                    {realm.name === active && (
                      <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                        acting
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 font-mono text-xs text-gray-400">{realm.name}</p>
                  <p className="mt-2 text-xs text-gray-600">
                    {realm.roles.length > 0 ? realm.roles.join(', ') : 'no role held'}
                  </p>
                  {/* The permissions in full, not a count: a grant away from home is usually
                      narrower than what its holder has at home, and only the list says how. */}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {realm.permissions.length === 0
                      ? <span className="text-xs text-gray-400">no permissions here</span>
                      : realm.permissions.map((permission) => (
                          <span
                            key={`${permission.resource}:${permission.action}`}
                            className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-600"
                          >
                            {permission.resource}:{permission.action}
                          </span>
                        ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-[#001E2B]">Grants handed out by this realm</h2>

        {mayManage && <GrantForm onGranted={() => void load()} onFailure={setError} />}

        {error && <ErrorState message={error} onRetry={() => void load()} />}

        {loading
          ? <LoadingState label="Reading cross-realm grants…" />
          : !mayView
            ? <EmptyState
                icon={Globe}
                title="You may not read cross-realm grants"
                description="Reading who administers another realm takes a role that permits viewing assignments."
              />
            : grants.length === 0
              ? <EmptyState
                  icon={Globe}
                  title="No principal of this realm administers another"
                  description="Every assignment here applies to this realm only. A grant that crosses the boundary would be listed here from the moment it is made."
                />
              : (
                <ul className="space-y-3">
                  {grants.map((grant) => (
                    <li key={grant.assignmentId} className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-semibold text-[#001E2B]">{grant.roleName ?? grant.roleId}</span>
                            <span className="text-xs text-gray-500">over</span>
                            <span className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[11px] font-semibold text-amber-800">
                              {grant.targetRealm ?? grant.targetRealmId}
                            </span>
                          </div>
                          <p className="mt-0.5 font-mono text-xs text-gray-400">held by {grant.subjectId}</p>
                          {grant.justification && (
                            <p className="mt-2 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">
                              {grant.justification}
                            </p>
                          )}
                          <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
                            <Fact label="Granted by" value={grant.grantedBy ?? 'seeded'} />
                            <Fact label="Granted" value={when(grant.grantedAt)} />
                            <Fact label="Expires" value={when(grant.expiresAt)} />
                          </dl>
                        </div>
                        {mayManage && (
                          <button
                            type="button"
                            disabled={busy === grant.assignmentId}
                            onClick={() => void revoke(grant)}
                            className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                          >
                            <Trash2 size={12} aria-hidden />
                            Take back
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
      </section>
    </main>
  );
}

/**
 * Granting one.
 *
 * Four things, all required, and the reason is one of them. A grant that crosses an isolation
 * boundary with no stated reason is the one an auditor finds and nobody can explain.
 */
function GrantForm({ onGranted, onFailure }: { onGranted: () => void; onFailure: (message: string) => void }) {
  const [open, setOpen] = useState(false);
  const [subjectId, setSubjectId] = useState('');
  const [targetRealm, setTargetRealm] = useState('');
  const [roleName, setRoleName] = useState('');
  const [justification, setJustification] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await callApi('/realm-grants', {
        method: 'POST',
        subject: 'that grant',
        body: {
          subjectId: subjectId.trim(),
          targetRealm: targetRealm.trim(),
          roleName: roleName.trim(),
          justification: justification.trim(),
          ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
        },
      });
      setSubjectId(''); setTargetRealm(''); setRoleName(''); setJustification(''); setExpiresAt('');
      setOpen(false);
      onGranted();
    } catch (failure) {
      onFailure(failure instanceof ApiError ? failure.message : 'That grant could not be made.');
    } finally {
      setSaving(false);
    }
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-semibold text-[#00ED64] transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <Plus size={13} aria-hidden />
        Grant administration of another realm
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <p className="text-xs text-gray-500">
        The role is one of THIS realm&apos;s roles, because a realm does not name another realm&apos;s roles.
        The principal stays here; only their reach changes.
      </p>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Principal" hint="Subject of this realm" value={subjectId} onChange={setSubjectId} required />
        <Field label="Realm to administer" hint="By name" value={targetRealm} onChange={setTargetRealm} required />
        <Field label="Role" hint="A role of this realm" value={roleName} onChange={setRoleName} required />
      </div>
      <label className="block">
        <span className="text-xs font-medium text-gray-700">Reason</span>
        <textarea
          value={justification}
          onChange={(event) => setJustification(event.target.value)}
          required
          rows={2}
          placeholder="Why this principal needs to reach across the boundary."
          className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-[#001E2B] focus:outline-none focus:ring-1 focus:ring-[#001E2B]"
        />
      </label>
      <label className="block sm:w-64">
        <span className="text-xs font-medium text-gray-700">Ends (optional)</span>
        <input
          type="datetime-local"
          value={expiresAt}
          onChange={(event) => setExpiresAt(event.target.value)}
          className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-[#001E2B] focus:outline-none focus:ring-1 focus:ring-[#001E2B]"
        />
      </label>
      <div className="flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={saving}
          className="rounded-lg border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-semibold text-[#00ED64] transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {saving ? 'Granting…' : 'Grant'}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-400"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

function Field({ label, hint, value, onChange, required }: {
  label: string;
  hint: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-gray-700">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        required={required}
        placeholder={hint}
        className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-[#001E2B] focus:outline-none focus:ring-1 focus:ring-[#001E2B]"
      />
    </label>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className="truncate text-gray-700" title={value}>{value}</dd>
    </div>
  );
}
