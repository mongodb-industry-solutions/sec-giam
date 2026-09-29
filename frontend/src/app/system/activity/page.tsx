'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, Search } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when, type Claims } from '../../../lib/console';
import { ExportJsonButton } from '../../../components/ExportJsonButton';
import { DateRangeFilter } from '../../../components/DateRangeFilter';
import { EMPTY_RANGE, rangeBounds, type DateRange } from '../../../lib/dateRange';
import { readAllSecurityEvents } from '../../../lib/securityEvents';

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
  principalSubjectId?: string;
  agentId?: string;
  stakeholder?: boolean;
  target?: { type: string; ref: string };
  detail?: { grantType?: string; clientName?: string; scope?: string[]; actedFor?: string };
}

type Scope = 'mine' | 'realm';
type Actor = '' | 'self' | 'application' | 'stakeholder';

/**
 * Who actually acted.
 *
 * `principalSubjectId` is written only when an application obtained authority FOR somebody, so its
 * presence is the distinction rather than a guess made from the action name.
 */
function actedByApplication(event: SecurityEvent): boolean {
  return Boolean(event.principalSubjectId) || event.detail?.actedFor === 'the principal';
}

/**
 * Why an event the reader did not cause is in their trail.
 *
 * The authority sets `stakeholder` when the reader is entitled to an event somebody else performed,
 * because it changed something of theirs. Without a word for it a reader sees a stranger's action in
 * their own activity and has no way to tell that from a mistake.
 */
function stakeholderReason(event: SecurityEvent): string {
  if (event.action.startsWith('client.owner')) return 'It changed who administers an application you own.';
  if (event.action.startsWith('client.')) return 'It changed an application you own.';
  if (event.action.startsWith('grant.')) return 'It changed an authorisation of yours.';
  if (event.action.startsWith('privilege.')) return 'It settled an elevation you asked for.';
  if (event.action.startsWith('authorization.cross_realm')) return 'It changed what you may administer.';
  return 'It changed something you hold.';
}

/** What to show in the application column: the registered name where there is one. */
function applicationOf(event: SecurityEvent): string | undefined {
  return event.detail?.clientName ?? event.agentId ?? event.clientId;
}

export default function ActivityPage() {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [scope, setScope] = useState<Scope>('mine');
  const [outcome, setOutcome] = useState('');
  const [action, setAction] = useState('');
  const [txn, setTxn] = useState('');
  const [actor, setActor] = useState<Actor>('');
  const [range, setRange] = useState<DateRange>(EMPTY_RANGE);
  // `txn` is the flow correlator an auditor reads off a token, which is the search that starts
  // most investigations.
  const [query, setQuery] = useState({ outcome: '', action: '', txn: '' });
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  // What MATCHES, not what was returned, so paging has something real to page against.
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Kept apart from `error`: that one's retry reloads the page, which is not how to retry an export.
  const [exportError, setExportError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(20);

  useEffect(() => { setClaims(currentClaims()); }, []);
  const mayReadRealm = can(claims, 'auditEvents', 'view');

  // What the authority is asked for, shared by the page read and the export so they cannot disagree.
  const filters = useMemo(() => ({
    ...(scope === 'mine' && claims ? { subjectId: claims.sub } : {}),
    ...(query.outcome ? { outcome: query.outcome } : {}),
    ...(query.action ? { action: query.action } : {}),
    ...(query.txn ? { txn: query.txn } : {}),
    ...(actor === 'stakeholder' ? { scope: 'stakeholder' } : {}),
    ...(actor === 'self' ? { actor: 'person' } : {}),
    ...(actor === 'application' ? { actor: 'application' } : {}),
    ...rangeBounds(range),
  }), [claims, scope, query, actor, range]);

  const load = useCallback(async () => {
    if (!claims) return;
    setLoading(true);
    try {
      /**
       * EVERY filter travels to the authority, and so does the paging.
       *
       * `actor` and the stakeholder narrowing were applied in the browser, and paging was a slice of
       * one fetched batch, so "page 5" showed whatever the limit had returned and nothing beyond it.
       * The header comment on the authority's own controller calls the first of those a defect: a
       * filter applied by a client after the fact is a presentation choice rather than an access
       * control, and it fails open the moment somebody calls the API directly.
       */
      const body = await callApi<{ events: SecurityEvent[]; total?: number }>('/security-events', {
        // Naming the subject asks for one person's slice; omitting it asks for the realm, which the
        // authority narrows back to the caller when their roles do not carry the wider view.
        query: { ...filters, offset: (page - 1) * limit, limit },
        subject: scope === 'mine' ? 'your activity' : "the realm's activity",
      });
      setEvents(body.events ?? []);
      setTotal(body.total ?? (body.events ?? []).length);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'The activity trail could not be read.');
    } finally {
      setLoading(false);
    }
  }, [claims, scope, filters, page, limit]);

  // Back to the first page whenever the SEARCH changes, but not when the page itself does, which
  // would make paging impossible.
  useEffect(() => { setPage(1); }, [filters]);
  useEffect(() => { void load(); }, [load]);

  // Nothing is narrowed here any more: the authority applied every filter and returned this page.
  const visible = events;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  /**
   * The filtered trail as a file: every event that matches, read from the authority at click time.
   *
   * It used to write `events`, which is the page on screen, while saying it wrote every match. A
   * page boundary is a display accident and an evidence file cut at one is misleading.
   */
  async function buildExport() {
    const all = await readAllSecurityEvents<SecurityEvent>(filters, 'the activity export');
    return {
      exportedAt: new Date().toISOString(),
      filters: {
        scope: scope === 'mine' ? 'the signed-in principal' : 'the whole realm',
        action: query.action || null,
        outcome: query.outcome || null,
        txn: query.txn || null,
        actor: actor || 'anyone',
        from: rangeBounds(range).from ?? null,
        to: rangeBounds(range).to ?? null,
      },
      count: all.length,
      events: all,
    };
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={Activity}
        title="Activity"
        description="Sign-ins, tokens, consent and lifecycle changes, newest first."
        info="Every entry says who did what, to what, when, and with what outcome. Failed attempts are recorded as carefully as successful ones, because a trail that only holds successes cannot show an attack that did not work. Some entries are somebody else's action: they appear here because they changed something you hold, such as who administers an application you own."
      />

      <form
        className="flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4"
        onSubmit={(event) => { event.preventDefault(); setQuery({ outcome, action, txn }); }}
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

        <div className="min-w-[16rem] flex-1">
          <label htmlFor="txn" className="mb-1 flex items-center gap-1 text-[10px] uppercase tracking-wider text-gray-500">
            Flow
            <Tooltip text="The txn claim an access token carries. Decompose a token, paste its txn here, and this shows every step of the flow that minted it: the authorization, the credential check, the redemption and every refresh." />
          </label>
          <input
            id="txn"
            value={txn}
            onChange={(event) => setTxn(event.target.value)}
            placeholder="paste the txn from a token"
            className="h-9 w-full rounded-lg border border-gray-200 px-2.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </div>

        <div>
          <span className="mb-1 flex items-center gap-1 text-[10px] uppercase tracking-wider text-gray-500">
            Who acted
            <Tooltip text="Whether you performed the action yourself, an application obtained authority to act for you, or somebody else did something that changed what you hold. All three are recorded; this only chooses which to show." />
          </span>
          <select
            id="actor"
            aria-label="Who acted"
            value={actor}
            onChange={(event) => { setActor(event.target.value as Actor); setPage(1); }}
            className="h-9 rounded-lg border border-gray-200 px-2.5 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          >
            <option value="">Anyone</option>
            <option value="self">The person</option>
            <option value="application">An application, on their behalf</option>
            <option value="stakeholder">Somebody else, affecting you</option>
          </select>
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

        <div>
          <span className="mb-1 block text-[10px] uppercase tracking-wider text-gray-500">When</span>
          <DateRangeFilter value={range} onChange={setRange} />
        </div>

        <ExportJsonButton
          filename="activity"
          count={total}
          noun="events"
          disabled={loading}
          build={() => { setExportError(null); return buildExport(); }}
          onError={(failure) => setExportError(failure instanceof ApiError ? failure.message : 'The export could not be read.')}
        />
      </form>
      {exportError && <p className="mt-2 text-xs text-red-700">{exportError}</p>}

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading the trail…" />
        : total === 0
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
                      <th scope="col" className="px-4 py-2.5 font-semibold">Who acted</th>
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
                          {event.detail?.grantType && <span className="ml-2 text-xs text-gray-400">{event.detail.grantType}</span>}
                          {event.cause && <span className="ml-2 text-xs text-gray-400">{event.cause}</span>}
                        </td>
                        <td className="px-4 py-2.5"><StatusBadge status={event.outcome} /></td>
                        <td className="whitespace-nowrap px-4 py-2.5 text-xs">
                          {actedByApplication(event)
                            ? <span className="rounded-md bg-amber-50 px-1.5 py-0.5 font-medium text-amber-700">On their behalf</span>
                            : <span className="text-gray-500">The person</span>}
                          {/* Only ever set for somebody else's action, so it never marks your own. */}
                          {event.stakeholder && (
                            <>
                              <span className="ml-1.5 rounded-md bg-sky-50 px-1.5 py-0.5 font-medium text-sky-700">Someone else</span>
                              <span className="mt-0.5 block whitespace-normal text-[10px] text-gray-500">{stakeholderReason(event)}</span>
                            </>
                          )}
                        </td>
                        <td className="max-w-40 truncate px-4 py-2.5 font-mono text-[11px] text-gray-500" title={event.subjectId}>
                          {event.principalSubjectId ?? event.subjectId ?? 'not stated'}
                        </td>
                        <td className="max-w-40 truncate px-4 py-2.5 text-[11px] text-gray-500" title={event.clientId}>
                          {applicationOf(event) ?? 'not stated'}
                          {event.detail?.scope?.length ? (
                            <span className="block truncate font-mono text-[10px] text-gray-400" title={event.detail.scope.join(' ')}>
                              {event.detail.scope.join(' ')}
                            </span>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination
                page={page}
                totalPages={totalPages}
                total={total}
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
