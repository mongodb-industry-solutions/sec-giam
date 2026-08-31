'use client';

import { useCallback, useEffect, useState } from 'react';
import { Activity, Search } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when, type Claims } from '../../../lib/console';

/**
 * The identity trail: who did what, when, and whether it succeeded.
 *
 * A person always sees their own. Seeing the whole realm is a permission, so the wider view is
 * offered only to a caller whose roles carry it. Only identity evidence is here; what an application
 * did with the access it was given stays with that application.
 */

interface SecurityEvent {
  ts: string;
  action: string;
  outcome: string;
  category?: string;
  cause?: string;
  subjectId?: string;
  clientId?: string;
  correlationId?: string;
}

type Scope = 'mine' | 'realm';

export default function ActivityPage() {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [scope, setScope] = useState<Scope>('mine');
  const [outcome, setOutcome] = useState('');
  const [action, setAction] = useState('');
  const [query, setQuery] = useState({ outcome: '', action: '' });
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);

  useEffect(() => { setClaims(currentClaims()); }, []);
  const mayReadRealm = can(claims, 'auditEvents', 'view');

  const load = useCallback(async () => {
    if (!claims) return;
    setLoading(true);
    try {
      const body = await callApi<{ events: SecurityEvent[] }>('/security-events', {
        // Naming the subject asks for one person's slice; omitting it asks for the realm, which the
        // authority narrows back to the caller when their roles do not carry the wider view.
        query: {
          ...(scope === 'mine' ? { subjectId: claims.sub } : {}),
          ...(query.outcome ? { outcome: query.outcome } : {}),
          ...(query.action ? { action: query.action } : {}),
          limit: 500,
        },
        subject: scope === 'mine' ? 'your activity' : "the realm's activity",
      });
      setEvents(body.events ?? []);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'The activity trail could not be read.');
    } finally {
      setLoading(false);
    }
  }, [claims, scope, query]);

  useEffect(() => { setPage(1); void load(); }, [load]);

  const totalPages = Math.max(1, Math.ceil(events.length / limit));
  const visible = events.slice((page - 1) * limit, page * limit);

  return (
    <main className="mx-auto w-full max-w-6xl space-y-5 p-4 sm:p-6 lg:p-8">
      <SectionHeader
        icon={Activity}
        title="Activity"
        description="Sign-ins, tokens, consent and lifecycle changes, newest first."
        info="Every entry says who did what, to what, when, and with what outcome. Failed attempts are recorded as carefully as successful ones, because a trail that only holds successes cannot show an attack that did not work."
      />

      <form
        className="flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4"
        onSubmit={(event) => { event.preventDefault(); setQuery({ outcome, action }); }}
      >
        {mayReadRealm && (
          <div>
            <span className="mb-1 flex items-center gap-1 text-[10px] uppercase tracking-wider text-gray-500">
              Whose
              <Tooltip text="Reading the whole realm's trail is a permission your roles carry. Without it this console shows you your own events only." />
            </span>
            <div className="flex gap-1 rounded-lg bg-gray-100 p-0.5" role="group" aria-label="Whose activity">
              {(['mine', 'realm'] as Scope[]).map((option) => (
                <button
                  key={option}
                  type="button"
                  onClick={() => setScope(option)}
                  aria-pressed={scope === option}
                  className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                    scope === option ? 'bg-[#001E2B] text-[#00ED64]' : 'text-gray-600 hover:bg-white'
                  }`}
                >
                  {option === 'mine' ? 'Mine' : 'Whole realm'}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="min-w-40 flex-1">
          <label htmlFor="action" className="mb-1 block text-[10px] uppercase tracking-wider text-gray-500">Action</label>
          <input
            id="action"
            value={action}
            onChange={(event) => setAction(event.target.value)}
            placeholder="token.issued"
            className="h-9 w-full rounded-lg border border-gray-200 px-2.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </div>

        <div>
          <label htmlFor="outcome" className="mb-1 block text-[10px] uppercase tracking-wider text-gray-500">Outcome</label>
          <select
            id="outcome"
            value={outcome}
            onChange={(event) => setOutcome(event.target.value)}
            className="h-9 rounded-lg border border-gray-200 px-2.5 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          >
            <option value="">Any</option>
            <option value="success">Succeeded</option>
            <option value="failure">Failed</option>
          </select>
        </div>

        <button
          type="submit"
          className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[#001E2B] px-3 text-xs font-semibold text-[#00ED64] transition-opacity hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          <Search size={13} aria-hidden />
          Search
        </button>
      </form>

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading the trail…" />
        : events.length === 0
          ? <EmptyState
              icon={Activity}
              title="No matching events"
              description="Nothing in the trail matches this search. Widen it, or clear the filters to see everything recorded."
            />
          : (
            <>
              <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white">
                <table className="w-full text-left text-sm">
                  <caption className="sr-only">Identity events, newest first</caption>
                  <thead className="border-b border-gray-200 bg-gray-50">
                    <tr className="text-[10px] uppercase tracking-wider text-gray-500">
                      <th scope="col" className="px-4 py-2.5 font-semibold">When</th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">Action</th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">Outcome</th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">Subject</th>
                      <th scope="col" className="px-4 py-2.5 font-semibold">Application</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {visible.map((event, index) => (
                      <tr key={`${event.ts}-${index}`} className="hover:bg-gray-50">
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs text-gray-500">{when(event.ts)}</td>
                        <td className="px-4 py-2.5">
                          <span className="font-mono text-xs text-[#001E2B]">{event.action}</span>
                          {event.cause && <span className="ml-2 text-xs text-gray-400">{event.cause}</span>}
                        </td>
                        <td className="px-4 py-2.5"><StatusBadge status={event.outcome} /></td>
                        <td className="max-w-40 truncate px-4 py-2.5 font-mono text-[11px] text-gray-500" title={event.subjectId}>
                          {event.subjectId ?? 'not stated'}
                        </td>
                        <td className="max-w-40 truncate px-4 py-2.5 font-mono text-[11px] text-gray-500" title={event.clientId}>
                          {event.clientId ?? 'not stated'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination
                page={page}
                totalPages={totalPages}
                total={events.length}
                limit={limit}
                noun="events"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}
