'use client';

import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, Plus, ShieldCheck, ShieldOff } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { ListToolbar } from '../../../components/ListToolbar';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../lib/console';
import { paginate } from '../../../lib/useConsoleResource';
import { useRealmChange } from '../../../lib/realms';
import { usePermissions } from '../../../lib/profile';

/**
 * Who holds temporary authority right now, and which requests are waiting.
 *
 * Time-bound and justified access rather than a standing permission, so the two questions worth
 * asking are answerable at any moment: who has it, and who is waiting for it. A queue nobody can see
 * is a request that expires unnoticed, which is why pending is a view here and not a notification.
 */

interface Elevation {
  /** The person behind the subject id. Absent when the record carries no name. */
  userName?: string;
  assignmentId: string;
  subjectId: string;
  roleId: string;
  scope?: { kind?: string; ref?: string };
  justification?: string;
  grantedBy?: string;
  approvalRef?: string;
  grantedAt?: string;
  notBefore?: string;
  expiresAt?: string;
  ephemeral?: boolean;
}

type State = 'in-force' | 'pending';

export default function ElevationsPage() {
  const [state, setState] = useState<State>('in-force');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  const [elevations, setElevations] = useState<Elevation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [mayApprove, setMayApprove] = useState(false);
  const { permissions } = usePermissions();

  useEffect(() => { setMayApprove(can(currentClaims(), 'elevations', 'approve')); }, [permissions]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const body = await callApi<{ elevations: Elevation[] }>('/elevations', {
        query: { state },
        subject: 'privileged access',
      });
      setElevations(body.elevations ?? []);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'Privileged access could not be read.');
    } finally {
      setLoading(false);
    }
  }, [state]);

  useEffect(() => { void load(); }, [load]);
  useRealmChange(() => { void load(); });

  const needle = query.trim().toLowerCase();
  const filtered = needle
    ? elevations.filter((elevation) => [elevation.roleId, elevation.userName, elevation.subjectId, elevation.justification]
        .some((field) => field?.toLowerCase().includes(needle)))
    : elevations;
  const totalPages = Math.max(1, Math.ceil(filtered.length / limit));
  const visible = paginate(filtered, page, limit);

  async function approve(elevation: Elevation) {
    setBusy(elevation.assignmentId);
    try {
      await callApi(`/elevations/${encodeURIComponent(elevation.assignmentId)}/approve`, {
        method: 'POST',
        subject: 'that request',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That request could not be approved.');
    } finally {
      setBusy(null);
    }
  }

  async function end(elevation: Elevation) {
    if (!window.confirm('End this elevation now? The authority it grants stops immediately.')) return;
    setBusy(elevation.assignmentId);
    try {
      await callApi(`/elevations/${encodeURIComponent(elevation.assignmentId)}`, {
        method: 'DELETE',
        body: { reason: 'Ended from the console.' },
        subject: 'that elevation',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That elevation could not be ended.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={ShieldCheck}
        title="Privileged access"
        description="Temporary authority: who holds it, why, and until when."
        info="Every elevation carries a stated reason and an expiry, and an approver can never be the requester. Ending one takes effect immediately rather than waiting for its expiry."
      />

      <ListToolbar
        search={{
          value: query,
          onChange: (next) => { setQuery(next); setPage(1); },
          placeholder: 'Role, subject or justification',
          label: 'Search privileged access',
        }}
        filter={{
          label: 'Filter by state',
          value: state,
          onChange: (next) => { setState(next); setPage(1); },
          options: [{ key: 'in-force', label: 'In force' }, { key: 'pending', label: 'Awaiting approval' }],
        }}
      />

      <RequestForm onRequested={() => void load()} onFailure={setError} />

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading privileged access…" />
        : filtered.length === 0
          ? <EmptyState
              icon={ShieldCheck}
              title={query ? 'No elevation matches that' : (state === 'in-force' ? 'Nobody holds elevated access' : 'Nothing is waiting for approval')}
              description={query
                ? 'Nothing in this view matches that role, subject or justification.'
                : (state === 'in-force'
                  ? 'No temporary authority is in force in this realm right now.'
                  : 'Every request has been decided. A new one appears here as soon as it is raised.')}
            />
          : (
            <>
            <ul className="space-y-3">
              {visible.map((elevation) => (
                <li key={elevation.assignmentId} className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-[#001E2B]">{elevation.roleId}</span>
                        {elevation.ephemeral && (
                          <Tooltip text="Held only for the length of this elevation. Nothing about it survives the expiry.">
                            <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                              ephemeral
                            </span>
                          </Tooltip>
                        )}
                      </div>
                      <p className="mt-0.5 text-xs text-gray-500">
                        held by <span className="font-medium text-gray-700">{elevation.userName ?? elevation.subjectId}</span>
                        {elevation.userName && <span className="ml-1.5 font-mono text-[10px] text-gray-400">{elevation.subjectId}</span>}
                      </p>

                      {elevation.justification && (
                        <p className="mt-2 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">
                          {elevation.justification}
                        </p>
                      )}

                      <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
                        <Fact label="Scope" value={elevation.scope?.ref ? `${elevation.scope.kind ?? 'scope'}: ${elevation.scope.ref}` : 'the whole realm'} />
                        <Fact label={state === 'pending' ? 'Requested' : 'In force since'} value={when(elevation.grantedAt ?? elevation.notBefore)} />
                        <Fact label="Expires" value={when(elevation.expiresAt)} />
                      </dl>
                    </div>

                    <div className="flex shrink-0 flex-wrap gap-2">
                      {state === 'pending' && mayApprove && (
                        <button
                          type="button"
                          disabled={busy === elevation.assignmentId}
                          onClick={() => void approve(elevation)}
                          className="inline-flex items-center gap-1.5 rounded-md border border-emerald-200 px-2.5 py-1.5 text-xs font-medium text-emerald-700 transition-colors hover:bg-emerald-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-emerald-500 disabled:opacity-50"
                        >
                          <CheckCircle2 size={12} aria-hidden />
                          Approve
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={busy === elevation.assignmentId}
                        onClick={() => void end(elevation)}
                        className="inline-flex items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                      >
                        <ShieldOff size={12} aria-hidden />
                        End now
                      </button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>

            <Pagination
              page={page}
              totalPages={totalPages}
              total={filtered.length}
              limit={limit}
              noun="elevations"
              onPageChange={setPage}
              onLimitChange={(next) => { setLimit(next); setPage(1); }}
            />
            </>
          )}
    </main>
  );
}

/**
 * Asking for temporary authority.
 *
 * The reason is required by the API and required here, and the field says why rather than only
 * marking itself mandatory: the moment of asking is the only time anybody actually knows the reason,
 * and an elevation with none cannot be reviewed afterwards. The scope is optional because an
 * elevation bound to one thing is narrower than one bound to the realm, and narrower is better when
 * the person can say what they are working on.
 */
function RequestForm({ onRequested, onFailure }: { onRequested: () => void; onFailure: (message: string) => void }) {
  const [open, setOpen] = useState(false);
  const [roleName, setRoleName] = useState('');
  const [justification, setJustification] = useState('');
  const [scopeKind, setScopeKind] = useState('');
  const [scopeRef, setScopeRef] = useState('');
  const [hours, setHours] = useState('4');
  const [saving, setSaving] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setSaving(true);
    try {
      await callApi('/elevations', {
        method: 'POST',
        subject: 'that request',
        body: {
          roleName: roleName.trim(),
          justification: justification.trim(),
          ...(scopeKind.trim() && scopeRef.trim() ? { scopeKind: scopeKind.trim(), scopeRef: scopeRef.trim() } : {}),
          ...(Number(hours) > 0 ? { durationSeconds: Math.round(Number(hours) * 3600) } : {}),
        },
      });
      setRoleName(''); setJustification(''); setScopeKind(''); setScopeRef(''); setHours('4');
      setOpen(false);
      onRequested();
    } catch (failure) {
      onFailure(failure instanceof ApiError ? failure.message : 'That elevation could not be requested.');
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
        Ask for temporary authority
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <p className="text-xs text-gray-500">
        The request is always for yourself, and where this realm reviews elevations it grants nothing
        until somebody else approves it. An approver can never be the requester.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        <ElevationField label="Role" hint="A role of this realm, by name" value={roleName} onChange={setRoleName} required />
        <ElevationField label="Hours" hint="Up to 12" value={hours} onChange={setHours} type="number" />
      </div>
      <label className="block">
        <span className="text-xs font-medium text-gray-700">Reason</span>
        <textarea
          value={justification}
          onChange={(event) => setJustification(event.target.value)}
          required
          rows={2}
          placeholder="What you are about to do, and why this authority is needed for it."
          className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-[#001E2B] focus:outline-none focus:ring-1 focus:ring-[#001E2B]"
        />
        <span className="mt-1 block text-[11px] text-gray-500">
          Required. An elevation with no stated reason cannot be reviewed afterwards, and now is the
          only time anybody knows it.
        </span>
      </label>
      <div className="grid gap-3 sm:grid-cols-2">
        <ElevationField label="Bound to (optional)" hint="What kind of thing, in your own words" value={scopeKind} onChange={setScopeKind} />
        <ElevationField label="Which one (optional)" hint="This authority never learns what it names" value={scopeRef} onChange={setScopeRef} />
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="submit"
          disabled={saving}
          className="rounded-lg border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-semibold text-[#00ED64] transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {saving ? 'Requesting…' : 'Request'}
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

function ElevationField({ label, hint, value, onChange, required, type }: {
  label: string;
  hint: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-gray-700">{label}</span>
      <input
        type={type ?? 'text'}
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
