'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Activity, Layers } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ApiError, callApi, when } from '../../../../lib/console';

/**
 * One authorization, and what was done under it.
 *
 * The operations list is the identity trail only. What the application did with the access is that
 * application's own record and stays there: two sources of truth for one event is worse than one.
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

interface Operation {
  ts: string;
  action: string;
  outcome: string;
  clientId?: string;
}

export default function GrantDetailPage() {
  const params = useParams<{ grantId: string }>();
  const grantId = decodeURIComponent(String(params.grantId ?? ''));

  const [grant, setGrant] = useState<Grant | null>(null);
  const [operations, setOperations] = useState<Operation[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [trailError, setTrailError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!grantId) return;
    setLoading(true);
    const path = `/grants/${encodeURIComponent(grantId)}`;
    try {
      setGrant(await callApi<Grant>(path, { subject: 'that authorization' }));
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authorization could not be loaded.');
      setLoading(false);
      return;
    }
    // The trail is read separately so a failure here leaves the authorization itself readable.
    try {
      const body = await callApi<{ operations: Operation[] }>(`${path}/operations`, { subject: 'this trail' });
      setOperations(body.operations);
      setTrailError(null);
    } catch (failure) {
      setTrailError(failure instanceof ApiError ? failure.message : 'The trail could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [grantId]);

  useEffect(() => { void load(); }, [load]);

  return (
    <main className="space-y-5">
      <Link
        href="/system/applications"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All authorized applications
      </Link>

      <SectionHeader
        icon={Layers}
        title={grant?.clientName || grant?.clientId || 'Authorization'}
        description={grant ? `Authorized ${when(grant.grantedAt)}` : 'One authorization and what was done under it.'}
        actions={grant ? <StatusBadge status={grant.status} /> : undefined}
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && <LoadingState label="Reading this authorization…" />}

      {grant && !loading && (
        <>
          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">The authorization</h2>
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              <Fact label="Application" value={grant.clientId} mono />
              <Fact label="Authorization" value={grant.grantId} mono />
              <Fact label="Last used" value={when(grant.lastUsedAt)} />
              <Fact label="Withdrawn" value={when(grant.revokedAt)} />
            </dl>
            <div className="mt-4">
              <p className="text-[10px] uppercase tracking-wider text-gray-400">Scopes approved</p>
              <div className="mt-1.5 flex flex-wrap gap-1">
                {grant.scopes.length === 0
                  ? <span className="text-sm text-gray-400">none</span>
                  : grant.scopes.map((scope) => (
                      <span key={scope} className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[11px] text-gray-600">
                        {scope}
                      </span>
                    ))}
              </div>
            </div>
          </section>

          <section className="space-y-3">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-[#001E2B]">
              <Activity size={15} className="text-gray-400" aria-hidden />
              Identity events under this authorization
            </h2>

            {trailError && <ErrorState message={trailError} onRetry={() => void load()} />}

            {!trailError && operations && (operations.length === 0
              ? <EmptyState
                  icon={Activity}
                  title="Nothing recorded yet"
                  description="No identity event has been recorded under this authorization. One appears the first time the application uses it."
                />
              : (
                <ul className="divide-y divide-gray-100 overflow-hidden rounded-xl border border-gray-200 bg-white">
                  {operations.map((operation, index) => (
                    <li key={`${operation.ts}-${index}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                      <span className="w-44 shrink-0 text-xs text-gray-500">{when(operation.ts)}</span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-[#001E2B]">{operation.action}</span>
                      <StatusBadge status={operation.outcome} />
                    </li>
                  ))}
                </ul>
              ))}
          </section>
        </>
      )}
    </main>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className={`truncate text-gray-700 ${mono ? 'font-mono text-xs' : ''}`} title={value}>{value}</dd>
    </div>
  );
}
