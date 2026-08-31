'use client';

import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, ShieldCheck, ShieldOff } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../lib/console';

/**
 * Who holds temporary authority right now, and which requests are waiting.
 *
 * Time-bound and justified access rather than a standing permission, so the two questions worth
 * asking are answerable at any moment: who has it, and who is waiting for it. A queue nobody can see
 * is a request that expires unnoticed, which is why pending is a view here and not a notification.
 */

interface Elevation {
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
  const [elevations, setElevations] = useState<Elevation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [mayApprove, setMayApprove] = useState(false);

  useEffect(() => { setMayApprove(can(currentClaims(), 'elevations', 'approve')); }, []);

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
    <main className="mx-auto w-full max-w-5xl space-y-5 p-4 sm:p-6 lg:p-8">
      <SectionHeader
        icon={ShieldCheck}
        title="Privileged access"
        description="Temporary authority: who holds it, why, and until when."
        info="Every elevation carries a stated reason and an expiry, and an approver can never be the requester. Ending one takes effect immediately rather than waiting for its expiry."
      />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by state">
        {(['in-force', 'pending'] as State[]).map((option) => (
          <button
            key={option}
            type="button"
            onClick={() => setState(option)}
            aria-pressed={state === option}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
              state === option
                ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]'
                : 'border-gray-200 bg-white text-gray-600 hover:border-gray-400'
            }`}
          >
            {option === 'in-force' ? 'In force' : 'Awaiting approval'}
          </button>
        ))}
      </div>

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading privileged access…" />
        : elevations.length === 0
          ? <EmptyState
              icon={ShieldCheck}
              title={state === 'in-force' ? 'Nobody holds elevated access' : 'Nothing is waiting for approval'}
              description={state === 'in-force'
                ? 'No temporary authority is in force in this realm right now.'
                : 'Every request has been decided. A new one appears here as soon as it is raised.'}
            />
          : (
            <ul className="space-y-3">
              {elevations.map((elevation) => (
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
                      <p className="mt-0.5 font-mono text-xs text-gray-400">held by {elevation.subjectId}</p>

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
          )}
    </main>
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
