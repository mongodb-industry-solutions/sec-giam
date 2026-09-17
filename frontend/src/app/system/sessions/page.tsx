'use client';

import { useCallback, useState } from 'react';
import { LogOut, MonitorSmartphone } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { ListToolbar } from '../../../components/ListToolbar';
import { SelectFilter } from '../../../components/SelectFilter';
import { RefreshButton } from '../../../components/RefreshButton';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, canReachOthers, currentClaims, when } from '../../../lib/console';
import { clearSession } from '../../../lib/session';
import { useConsoleResource } from '../../../lib/useConsoleResource';
import { usePermissions } from '../../../lib/profile';
import { useConfirm } from '../../../components/ConfirmProvider';

/**
 * Where an account is signed in, and ending it.
 *
 * The one administrative screen that is also an ordinary account-security screen. Everybody sees
 * their own sessions and can end one, because seeing where you are signed in and being able to stop
 * it is not a privilege. Somebody who administers the realm sees everybody's, and the authority
 * decides which of the two answers it gives: this screen asks, it does not filter.
 *
 * Ending your own current session signs you out here rather than leaving the console holding a token
 * that has just been revoked.
 */

interface Session {
  /** The person behind the subject id. Absent when the record carries no name. */
  userName?: string;
  sessionId: string;
  subjectId: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  clientIds: string[];
  /** The same applications by registered name, positionally aligned with `clientIds`. */
  applications: string[];
  current: boolean;
  origin?: { addressFingerprint?: string; deviceFingerprint?: string };
}

type Scope = 'mine' | 'realm';

interface Application { clientId: string; clientName: string; }

export default function SessionsPage() {
  const confirm = useConfirm();
  // Read fresh, not from the token: the token carries roles by default, not entitlements, so
  // `can()` needs the effective-permissions read this hook keeps warm to answer correctly.
  usePermissions();
  // The permission AND the realm-wide scope, because that is the conjunction the authority applies.
  // Gating on the permission alone would offer a self-scoped holder a filter answering 403.
  const claims = currentClaims();
  const mayViewRealm = canReachOthers(claims, 'sessions', 'view');
  const mayEndOthers = canReachOthers(claims, 'sessions', 'manage');
  const [scope, setScope] = useState<Scope>('mine');
  const [search, setSearch] = useState('');
  const [clientId, setClientId] = useState('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);
  /**
   * The rows picked for a bulk action, by session id.
   *
   * By id rather than by index, because the list is re-read: after a refresh or a termination the
   * row at position three is a different session, and a selection held by position would end the
   * wrong one.
   */
  const [picked, setPicked] = useState<ReadonlySet<string>>(new Set());

  const read = useCallback(
    () => callApi<{ sessions: Session[]; total: number; scope: Scope; applications: Application[] }>('/sessions', {
      query: {
        scope,
        // Searching people is a question about other people, so it only travels with the realm
        // scope. Sent with `scope=mine` the authority would refuse it, which is the right refusal
        // and the wrong moment to show it.
        q: scope === 'realm' && search.trim() ? search.trim() : undefined,
        // The application filter is not scoped: narrowing your own sessions to one application is
        // still a question about yourself.
        clientId: clientId || undefined,
        skip: (page - 1) * limit,
        limit,
      },
      subject: 'the active sessions',
    }),
    [scope, search, clientId, page, limit],
  );
  const sessions = useConsoleResource(read, 'The sessions could not be read.');

  const rows = sessions.data?.sessions ?? [];
  const applications = sessions.data?.applications ?? [];

  // Your own session is always yours to end, whatever the role says.
  const mine = (session: Session) => session.subjectId === claims?.sub;
  const total = sessions.data?.total ?? 0;

  // Only what is still on screen can be acted on: a selection surviving a filter change would
  // apply to rows the person can no longer see.
  const selectable = rows.filter((session) => mine(session) || mayEndOthers);
  const selected = selectable.filter((session) => picked.has(session.sessionId));
  const allSelected = selectable.length > 0 && selected.length === selectable.length;

  function toggle(sessionId: string) {
    setPicked((held) => {
      const next = new Set(held);
      if (next.has(sessionId)) next.delete(sessionId); else next.add(sessionId);
      return next;
    });
  }

  function toggleAll() {
    setPicked(allSelected ? new Set() : new Set(selectable.map((session) => session.sessionId)));
  }

  /**
   * Ending a selection.
   *
   * One request rather than one per row, so the authority decides the order and leaves the caller's
   * own session for last. Doing it from here in a loop would revoke the token mid-way through and
   * fail the rest.
   */
  async function terminateSelected() {
    const ids = selected.map((session) => session.sessionId);
    if (ids.length === 0) return;
    const endingOwn = selected.some((session) => session.current);
    if (!(await confirm(endingOwn
      ? `End ${ids.length} sessions? One of them is the session you are signed in with, so you will be signed out.`
      : `End ${ids.length} sessions? Every application holding a token from them is told, and the tokens stop working.`))) return;

    await sessions.run(
      'selection',
      async () => {
        const outcome = await callApi<{ terminated: number; wasCurrentSession: boolean }>(
          '/sessions/terminate',
          { method: 'POST', body: { sessionIds: ids }, subject: 'those sessions' },
        );
        setPicked(new Set());
        if (outcome?.wasCurrentSession) {
          clearSession();
          window.location.replace('/auth/login');
        }
        return outcome;
      },
      'Those sessions could not be ended.',
    );
  }

  async function terminate(session: Session) {
    if (!(await confirm(session.current
      ? 'End this session? It is the one you are signed in with, so you will be signed out.'
      : 'End this session? Every application holding a token from it is told, and the tokens stop working.'))) return;

    await sessions.run(
      session.sessionId,
      async () => {
        const outcome = await callApi<{ wasCurrentSession: boolean }>(
          `/sessions/${encodeURIComponent(session.sessionId)}`,
          { method: 'DELETE', subject: 'that session' },
        );
        // The authority says whether the token in this browser is the one just revoked, rather than
        // the console guessing from an identifier it happens to hold.
        if (outcome?.wasCurrentSession) {
          clearSession();
          window.location.replace('/auth/login');
        }
        return outcome;
      },
      'That session could not be ended.',
    );
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={MonitorSmartphone}
        title="Sessions"
        description="Where this account is signed in, and ending it everywhere at once."
        info={
          <>
            Ending a session revokes the tokens issued under it, raises the account&apos;s epoch so
            anything unrecorded is retired too, and notifies every application holding one. The origin
            is a short fingerprint of values stored hashed: the address and the device are never kept.
          </>
        }
      />

      <ListToolbar
        search={mayViewRealm && scope === 'realm'
          ? {
              value: search,
              onChange: (next) => { setSearch(next); setPage(1); },
              placeholder: 'User name or subject id',
              label: 'Search sessions by user name or subject id',
            }
          : undefined}
        filter={mayViewRealm
          ? {
              label: 'Whose sessions',
              value: scope,
              // The search only applies realm-wide, so going back to your own clears it rather than
              // leaving a term in the box that is no longer being applied.
              onChange: (next) => { setScope(next); setSearch(''); setPage(1); },
              options: [{ key: 'mine', label: 'Mine' }, { key: 'realm', label: 'Everyone in this realm' }],
            }
          : undefined}
        extra={
          <>
            <SelectFilter
              label="Filter by application"
              anyLabel="Any application"
              value={clientId}
              onChange={(next) => { setClientId(next); setPage(1); }}
              options={applications.map((application) => ({
                key: application.clientId,
                label: application.clientName,
              }))}
            />
            <RefreshButton
              onClick={() => void sessions.reload()}
              busy={sessions.loading}
              hint="Sessions open and lapse while this list is on screen. This re-reads it."
            />
          </>
        }
      />

      {selectable.length > 0 && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
          <label className="flex items-center gap-2 text-xs text-gray-600">
            <input
              type="checkbox"
              checked={allSelected}
              // Neither all nor none, so the box shows the third state rather than implying "none".
              ref={(box) => { if (box) box.indeterminate = selected.length > 0 && !allSelected; }}
              onChange={toggleAll}
              className="h-3.5 w-3.5 rounded border-gray-300 text-[#001E2B] focus:ring-[#00ED64]"
            />
            Select all on this page
          </label>
          <span className="text-xs text-gray-500">
            {selected.length === 0 ? 'None selected' : `${selected.length} selected`}
          </span>
          {selected.length > 0 && (
            <ActionButton
              icon={LogOut}
              label={`End ${selected.length} sessions`}
              tone="danger"
              busy={sessions.busy === 'selection'}
              onClick={() => void terminateSelected()}
            />
          )}
        </div>
      )}

      {sessions.error && <ErrorState message={sessions.error} onRetry={() => void sessions.reload()} />}

      {sessions.loading && rows.length === 0
        ? <LoadingState label="Reading sessions…" />
        : rows.length === 0
          ? <EmptyState
              icon={MonitorSmartphone}
              // A filtered empty list and a genuinely empty one are different answers, and saying
              // "nobody is signed in" when a filter is on is simply wrong.
              title={search.trim() || clientId ? 'Nothing matches those filters' : scope === 'mine' ? 'No other session is open' : 'Nobody is signed in'}
              description={search.trim() || clientId
                ? 'No live session matches. Clear the filters to see the rest.'
                : scope === 'mine'
                  ? 'This account is not signed in anywhere the authority has a record of.'
                  : 'No live session exists in this realm right now.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {rows.map((session) => (
                  <RecordCard
                    key={session.sessionId}
                    href={`/system/sessions/${encodeURIComponent(session.sessionId)}`}
                    lead={mine(session) || mayEndOthers
                      ? (
                        <input
                          type="checkbox"
                          checked={picked.has(session.sessionId)}
                          onChange={() => toggle(session.sessionId)}
                          aria-label={`Select the session of ${session.userName ?? session.subjectId}`}
                          className="h-3.5 w-3.5 rounded border-gray-300 text-[#001E2B] focus:ring-[#00ED64]"
                        />
                      )
                      : undefined}
                    // The person, with the identifiers as the supporting detail. A list of sessions
                    // titled by subject id names nobody a reviewer can recognise.
                    title={session.userName ?? session.subjectId}
                    subtitle={session.userName ? `${session.subjectId} · ${session.sessionId}` : session.sessionId}
                    badges={session.current
                      ? (
                        <Tooltip text="The session your current token was issued under. Ending it signs you out here.">
                          <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                            this browser
                          </span>
                        </Tooltip>
                      )
                      : undefined}
                    facts={
                      <>
                        <Fact label="Signed in" value={when(session.createdAt)} />
                        <Fact label="Last seen" value={when(session.lastSeenAt)} />
                        <Fact label="Ends at" value={when(session.expiresAt)} />
                        <Fact label="Idle timeout" value={when(session.idleExpiresAt)} />
                        <Fact
                          label="Applications"
                          // By registered name, with the ids behind the tooltip: the name is what a
                          // reviewer recognises, the id is what a support question is phrased in.
                          value={session.applications.length === 0
                            ? 'none holding a token'
                            : session.applications.join(', ')}
                          title={session.clientIds.length > 0 ? session.clientIds.join(', ') : undefined}
                        />
                        <Fact
                          label="Origin"
                          value={session.origin?.addressFingerprint || session.origin?.deviceFingerprint
                            ? `${session.origin.addressFingerprint ?? '—'} / ${session.origin.deviceFingerprint ?? '—'}`.replace(/—/g, 'unknown')
                            : 'not recorded'}
                          title="A short one-way fingerprint of the address and the user agent. Neither is stored raw."
                        />
                      </>
                    }
                    // Somebody else's session needs `sessions:manage`, and without it the
                    // authority answers 404. An auditor holds `view` and not `manage`, so the
                    // control is absent there rather than present and failing.
                    actions={mine(session) || mayEndOthers
                      ? (
                        <ActionButton
                          icon={LogOut}
                          label={session.current ? 'Sign out here' : 'End session'}
                          tone="danger"
                          busy={sessions.busy === session.sessionId}
                          onClick={() => void terminate(session)}
                        />
                      )
                      : undefined}
                  />
                ))}
              </ul>

              <Pagination
                page={page}
                totalPages={Math.max(1, Math.ceil(total / limit))}
                total={total}
                limit={limit}
                noun="sessions"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            </>
          )}
    </main>
  );
}
