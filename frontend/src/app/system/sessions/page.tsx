'use client';

import { useCallback, useState } from 'react';
import { LogOut, MonitorSmartphone } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { Pagination } from '../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, FilterGroup, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../lib/console';
import { clearSession } from '../../../lib/session';
import { useConsoleResource } from '../../../lib/useConsoleResource';

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
  sessionId: string;
  subjectId: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  clientIds: string[];
  current: boolean;
  origin?: { addressFingerprint?: string; deviceFingerprint?: string };
}

type Scope = 'mine' | 'realm';

export default function SessionsPage() {
  const mayViewRealm = can(currentClaims(), 'sessions', 'view');
  const [scope, setScope] = useState<Scope>('mine');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const read = useCallback(
    () => callApi<{ sessions: Session[]; total: number; scope: Scope }>('/sessions', {
      query: { scope, skip: (page - 1) * limit, limit },
      subject: 'the active sessions',
    }),
    [scope, page, limit],
  );
  const sessions = useConsoleResource(read, 'The sessions could not be read.');

  const rows = sessions.data?.sessions ?? [];
  const total = sessions.data?.total ?? 0;

  async function terminate(session: Session) {
    if (!window.confirm(session.current
      ? 'End this session? It is the one you are signed in with, so you will be signed out.'
      : 'End this session? Every application holding a token from it is told, and the tokens stop working.')) return;

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

      {mayViewRealm && (
        <FilterGroup
          label="Whose sessions"
          value={scope}
          onChange={(next) => { setScope(next); setPage(1); }}
          options={[{ key: 'mine', label: 'Mine' }, { key: 'realm', label: 'Everyone in this realm' }]}
        />
      )}

      {sessions.error && <ErrorState message={sessions.error} onRetry={() => void sessions.reload()} />}

      {sessions.loading && rows.length === 0
        ? <LoadingState label="Reading sessions…" />
        : rows.length === 0
          ? <EmptyState
              icon={MonitorSmartphone}
              title={scope === 'mine' ? 'No other session is open' : 'Nobody is signed in'}
              description={scope === 'mine'
                ? 'This account is not signed in anywhere the authority has a record of.'
                : 'No live session exists in this realm right now.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {rows.map((session) => (
                  <RecordCard
                    key={session.sessionId}
                    title={session.subjectId}
                    subtitle={session.sessionId}
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
                          value={session.clientIds.length === 0 ? 'none holding a token' : session.clientIds.join(', ')}
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
                    actions={
                      <ActionButton
                        icon={LogOut}
                        label={session.current ? 'Sign out here' : 'End session'}
                        tone="danger"
                        busy={sessions.busy === session.sessionId}
                        onClick={() => void terminate(session)}
                      />
                    }
                  />
                ))}
              </ul>

              {scope === 'realm' && (
                <Pagination
                  page={page}
                  totalPages={Math.max(1, Math.ceil(total / limit))}
                  total={total}
                  limit={limit}
                  noun="sessions"
                  onPageChange={setPage}
                  onLimitChange={(next) => { setLimit(next); setPage(1); }}
                />
              )}
            </>
          )}
    </main>
  );
}
