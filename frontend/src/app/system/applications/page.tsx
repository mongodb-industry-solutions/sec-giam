'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Layers, RotateCcw, ShieldOff } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { ApiError, callApi, when } from '../../../lib/console';

/**
 * What this principal has authorized, and taking it back.
 *
 * Withdrawn authorizations stay on the list rather than disappearing, because "what did I once allow,
 * and when did I stop" is the question that matters after something goes wrong.
 */

interface Grant {
  grantId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  status: 'active' | 'revoked';
  grantedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
}

type Filter = 'all' | 'active' | 'revoked';

const FILTERS: Array<{ key: Filter; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'active', label: 'Active' },
  { key: 'revoked', label: 'Withdrawn' },
];

export default function ApplicationsPage() {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [filter, setFilter] = useState<Filter>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const body = await callApi<{ grants: Grant[] }>('/grants', {
        query: { status: filter },
        subject: 'your authorized applications',
      });
      setGrants(body.grants);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'Your authorized applications could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => { setPage(1); void load(); }, [load]);

  async function change(grant: Grant, action: 'revoke' | 'reactivate') {
    if (action === 'revoke'
      && !window.confirm(`Withdraw ${grant.clientName}? It stops acting for you immediately.`)) return;
    setBusy(grant.grantId);
    try {
      await callApi(`/grants/${encodeURIComponent(grant.grantId)}${action === 'revoke' ? '' : '/reactivate'}`, {
        method: action === 'revoke' ? 'DELETE' : 'POST',
        subject: 'that authorization',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authorization could not be changed.');
    } finally {
      setBusy(null);
    }
  }

  const totalPages = Math.max(1, Math.ceil(grants.length / limit));
  const visible = grants.slice((page - 1) * limit, page * limit);

  return (
    <main className="mx-auto w-full max-w-5xl space-y-5 p-4 sm:p-6 lg:p-8">
      <SectionHeader
        icon={Layers}
        title="Authorized applications"
        description="Applications allowed to act for you, and what each one was allowed to do."
        info="Withdrawing an authorization stops the application immediately. It stays on this list, marked withdrawn, so the record of what was once allowed survives the withdrawal."
      />

      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by state">
        {FILTERS.map((option) => (
          <button
            key={option.key}
            type="button"
            onClick={() => setFilter(option.key)}
            aria-pressed={filter === option.key}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
              filter === option.key
                ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]'
                : 'border-gray-200 bg-white text-gray-600 hover:border-gray-400'
            }`}
          >
            {option.label}
          </button>
        ))}
      </div>

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading your authorizations…" />
        : grants.length === 0
          ? <EmptyState
              icon={Layers}
              title="No authorizations to show"
              description={filter === 'all'
                ? 'You have not allowed any application to act for you yet. One appears here the first time you approve a sign-in request.'
                : 'Nothing in this state. Try another filter.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {visible.map((grant) => (
                  <li key={grant.grantId} className={`rounded-xl border border-gray-200 bg-white p-4 shadow-sm ${grant.status === 'revoked' ? 'opacity-70' : ''}`}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <Link
                            href={`/system/applications/${encodeURIComponent(grant.grantId)}`}
                            className="font-semibold text-[#001E2B] hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
                          >
                            {grant.clientName || grant.clientId}
                          </Link>
                          <StatusBadge status={grant.status} />
                        </div>
                        <p className="mt-0.5 font-mono text-xs text-gray-400">{grant.clientId}</p>
                        <p className="mt-2 text-xs text-gray-500">
                          Authorized {when(grant.grantedAt)}
                          {grant.lastUsedAt && ` · last used ${when(grant.lastUsedAt)}`}
                          {grant.revokedAt && ` · withdrawn ${when(grant.revokedAt)}`}
                        </p>
                        <div className="mt-2 flex flex-wrap items-center gap-1">
                          <Tooltip text="The permissions this application asked for and you approved. It can do nothing outside them.">
                            <span className="mr-1 text-[10px] uppercase tracking-wider text-gray-400">Scopes</span>
                          </Tooltip>
                          {grant.scopes.length === 0
                            ? <span className="text-xs text-gray-400">none</span>
                            : grant.scopes.map((scope) => (
                                <span key={scope} className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-600">
                                  {scope}
                                </span>
                              ))}
                        </div>
                      </div>

                      <button
                        type="button"
                        disabled={busy === grant.grantId}
                        onClick={() => void change(grant, grant.status === 'active' ? 'revoke' : 'reactivate')}
                        className={`inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 disabled:opacity-50 ${
                          grant.status === 'active'
                            ? 'border-red-200 text-red-700 hover:bg-red-50 focus-visible:ring-red-500'
                            : 'border-gray-300 text-gray-700 hover:bg-gray-50 focus-visible:ring-[#00ED64]'
                        }`}
                      >
                        {grant.status === 'active'
                          ? <><ShieldOff size={12} aria-hidden /> Withdraw</>
                          : <><RotateCcw size={12} aria-hidden /> Restore</>}
                      </button>
                    </div>
                  </li>
                ))}
              </ul>

              <Pagination
                page={page}
                totalPages={totalPages}
                total={grants.length}
                limit={limit}
                noun="applications"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}
