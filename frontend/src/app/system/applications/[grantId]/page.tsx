'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Activity, Layers } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ListToolbar } from '../../../../components/ListToolbar';
import { Pagination } from '../../../../components/Pagination';
import { ExportJsonButton } from '../../../../components/ExportJsonButton';
import { ApiError, callApi, when } from '../../../../lib/console';
import { useLocalList } from '../../../../lib/useLocalList';
import { DateRangeFilter } from '../../../../components/DateRangeFilter';
import { EMPTY_RANGE, inRange, rangeBounds, type DateRange } from '../../../../lib/dateRange';

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
  registeredScopes: string[];
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
            <ScopeEditor grant={grant} onChanged={() => void load()} />
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
              : <OperationsTrail grant={grant} operations={operations} />)}
          </section>
        </>
      )}
    </main>
  );
}

type OutcomeFilter = 'all' | 'success' | 'failure';

const OUTCOME_OPTIONS: Array<{ key: OutcomeFilter; label: string }> = [
  { key: 'all', label: 'All' },
  { key: 'success', label: 'Succeeded' },
  { key: 'failure', label: 'Failed' },
];

const matchesOperation = (operation: Operation, needle: string) =>
  [operation.action, operation.outcome, operation.clientId ?? ''].some((field) => field.toLowerCase().includes(needle));
const outcomeIs = (operation: Operation, filter: OutcomeFilter) => filter === 'all' || operation.outcome === filter;

/** The trail as it was read: searched, filtered and paged here, since the read is bounded. */
function OperationsTrail({ grant, operations }: { grant: Grant; operations: Operation[] }) {
  const [range, setRange] = useState<DateRange>(EMPTY_RANGE);
  const inWindow = useMemo(() => operations.filter((operation) => inRange(operation.ts, range)), [operations, range]);
  const list = useLocalList(inWindow, { matches: matchesOperation, filterBy: outcomeIs, initialFilter: 'all' as OutcomeFilter });

  return (
    <>
      <ListToolbar
        search={{ value: list.search, onChange: list.setSearch, placeholder: 'Search action, outcome or application', label: 'Search events' }}
        filter={{ label: 'Outcome', options: OUTCOME_OPTIONS, value: list.filter, onChange: list.setFilter }}
        extra={(
          <>
          <DateRangeFilter value={range} onChange={setRange} />
          <ExportJsonButton
            filename={`grant-${grant.grantId}-events`}
            count={list.filtered.length}
            noun="events"
            // Every match, not the page on screen: a page boundary is a display accident.
            build={() => ({
              exportedAt: new Date().toISOString(),
              grantId: grant.grantId,
              clientId: grant.clientId,
              filters: { search: list.search.trim() || null, outcome: list.filter, ...rangeBounds(range) },
              count: list.filtered.length,
              operations: list.filtered,
            })}
          />
          </>
        )}
      />

      {list.filtered.length === 0
        ? <EmptyState icon={Activity} title="No matching events" description="Nothing in this trail matches the search. Widen it, or clear the filters." />
        : (
          <ul className="divide-y divide-gray-100 overflow-hidden rounded-xl border border-gray-200 bg-white">
            {list.visible.map((operation, index) => (
              <li key={`${operation.ts}-${index}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <span className="w-44 shrink-0 text-xs text-gray-500">{when(operation.ts)}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-[#001E2B]">{operation.action}</span>
                <StatusBadge status={operation.outcome} />
              </li>
            ))}
          </ul>
        )}

      <Pagination {...list.pagination} noun="events" />
    </>
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

/**
 * Choosing, afterwards, what an application is allowed to do.
 *
 * The list is everything the client is REGISTERED for, not just what was approved, because a person
 * who declined something at consent time must be able to change their mind. Offering only what is
 * held would make consent a one-way door: every choice could be narrowed and none restored.
 *
 * A change is sent as the complete set rather than a delta. A delta has to be resolved against a
 * state the caller may have read minutes ago; a set says what the answer should be and cannot be
 * misapplied against a stale view.
 *
 * The result is stated rather than implied. Narrowing ends the application's sessions so the next
 * token is minted narrower, but a token already issued keeps its scope until it expires, because it
 * is verified without calling the authority. That window is minutes, and saying "immediately" would
 * be false.
 */
function ScopeEditor({ grant, onChanged }: { grant: Grant; onChanged: () => void }) {
  const [selected, setSelected] = useState<string[]>(grant.scopes);
  const [saving, setSaving] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<string | null>(null);

  // Re-seeded when the grant is reloaded, so the boxes follow the authority rather than the last
  // thing that was clicked.
  useEffect(() => { setSelected(grant.scopes); setOutcome(null); }, [grant]);

  const offered = grant.registeredScopes.length > 0 ? grant.registeredScopes : grant.scopes;
  const held = new Set(grant.scopes);
  const dirty = selected.length !== grant.scopes.length
    || selected.some((scope) => !held.has(scope));
  const editable = grant.status === 'active';

  function toggle(scope: string) {
    setSelected((current) => (current.includes(scope)
      ? current.filter((entry) => entry !== scope)
      : [...current, scope]));
  }

  async function save() {
    setSaving(true);
    setFailure(null);
    setOutcome(null);
    try {
      const body = await callApi<{ added: string[]; removed: string[]; sessionsEnded: number }>(
        `/grants/${encodeURIComponent(grant.grantId)}`,
        { method: 'PATCH', body: { scopes: selected }, subject: 'these permissions' },
      );
      const parts = [
        body.added.length > 0 ? `added ${body.added.join(', ')}` : '',
        body.removed.length > 0 ? `removed ${body.removed.join(', ')}` : '',
      ].filter(Boolean);
      setOutcome(
        `${parts.length > 0 ? `${parts.join(' and ')}. ` : ''}`
        + `${body.sessionsEnded} session${body.sessionsEnded === 1 ? '' : 's'} ended. `
        + 'A token already issued keeps what it had until it expires, which is minutes.',
      );
      onChanged();
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : 'These permissions could not be changed.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mt-4">
      <p className="text-[10px] uppercase tracking-wider text-gray-400">
        {editable ? 'Permissions' : 'Scopes approved'}
      </p>

      {offered.length === 0
        ? <p className="mt-1.5 text-sm text-gray-400">none</p>
        : (
          <ul className="mt-1.5 space-y-1.5">
            {offered.map((scope) => (
              <li key={scope}>
                <label className={`flex items-center gap-2 text-sm ${editable ? 'cursor-pointer' : ''}`}>
                  <input
                    type="checkbox"
                    checked={selected.includes(scope)}
                    disabled={!editable || saving}
                    onChange={() => toggle(scope)}
                    className="h-4 w-4 rounded border-gray-300 text-[#001E2B] focus:ring-[#00ED64] disabled:opacity-50"
                  />
                  <span className="font-mono text-[11px] text-gray-700">{scope}</span>
                  {!held.has(scope) && (
                    <span className="text-[10px] uppercase tracking-wider text-gray-400">not granted</span>
                  )}
                </label>
              </li>
            ))}
          </ul>
        )}

      {editable && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={!dirty || saving}
            onClick={() => void save()}
            className="rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:opacity-90 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-40"
          >
            {saving ? 'Saving…' : 'Save permissions'}
          </button>
          {dirty && !saving && (
            <button
              type="button"
              onClick={() => setSelected(grant.scopes)}
              className="rounded-md border border-gray-300 px-3 py-1.5 text-xs text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
            >
              Reset
            </button>
          )}
        </div>
      )}

      {failure && <p className="mt-2 text-xs text-red-700">{failure}</p>}
      {outcome && <p className="mt-2 text-xs text-gray-600">{outcome}</p>}
    </div>
  );
}
