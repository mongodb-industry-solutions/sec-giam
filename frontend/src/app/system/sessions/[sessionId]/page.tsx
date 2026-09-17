'use client';

import { useCallback } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, LogOut, MonitorSmartphone, ShieldCheck, UserRound } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ActionButton, Fact } from '../../../../components/RecordCard';
import { RefreshButton } from '../../../../components/RefreshButton';
import { callApi, when } from '../../../../lib/console';
import { clearSession } from '../../../../lib/session';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { useConfirm } from '../../../../components/ConfirmProvider';

/**
 * One session in full.
 *
 * NO TOKEN IS SHOWN HERE, and none is available to show. This authority stores no token: an access
 * token and a refresh token are both JWTs, verified without a database read, and revocation works by
 * the absence of the session record plus the epoch. There is therefore no token history to display,
 * and this page says so rather than leaving a blank where a reader would assume one was hidden.
 *
 * What governs the tokens of this session IS here: the epoch that retires them, the refresh
 * generation that detects a replayed one, and the assurance the sign-in reached. That is what a
 * reviewer needs in order to reason about what is still valid.
 *
 * The owner is named and linked rather than restated. Their email and phone are encrypted personal
 * data, and looking at a session is not a reason to decrypt them; the identity page is where a
 * principal is read.
 */

interface SessionDetail {
  session: {
    sessionId: string;
    subjectId: string;
    userName?: string;
    createdAt: string;
    lastSeenAt: string;
    expiresAt: string;
    idleExpiresAt: string;
    clientIds: string[];
    applications: string[];
    current: boolean;
    origin?: { addressFingerprint?: string; deviceFingerprint?: string };
  };
  owner: {
    subjectId: string;
    userName?: string;
    kind?: string;
    active?: boolean;
    lifecycleState?: string;
  };
  authentication: {
    domainId?: string;
    domainName?: string;
    establishedForClientId?: string;
    establishedForClientName?: string;
    acr?: string;
    amr?: string[];
    credentialId?: string;
    ticketId?: string;
    epoch: number;
    refreshGeneration: number;
    tokensStored: boolean;
  };
}

export default function SessionDetailPage() {
  const confirm = useConfirm();
  const router = useRouter();
  const sessionId = String(useParams().sessionId ?? '');

  const read = useCallback(
    () => callApi<SessionDetail>(`/sessions/${encodeURIComponent(sessionId)}`, { subject: 'that session' }),
    [sessionId],
  );
  const detail = useConsoleResource(read, 'That session could not be read.');
  const data = detail.data;

  async function terminate() {
    if (!data) return;
    if (!(await confirm(data.session.current
      ? 'End this session? It is the one you are signed in with, so you will be signed out.'
      : 'End this session? Every application holding a token from it is told, and the tokens stop working.'))) return;

    await detail.run(
      sessionId,
      async () => {
        const outcome = await callApi<{ wasCurrentSession: boolean }>(
          `/sessions/${encodeURIComponent(sessionId)}`,
          { method: 'DELETE', subject: 'that session' },
        );
        if (outcome?.wasCurrentSession) {
          clearSession();
          window.location.replace('/auth/login');
          return outcome;
        }
        // The record is gone, so there is nothing left for this page to show.
        router.replace('/system/sessions');
        return outcome;
      },
      'That session could not be ended.',
    );
  }

  return (
    <main className="space-y-5">
      <Link href="/system/sessions" className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]">
        <ArrowLeft size={13} aria-hidden />
        All sessions
      </Link>

      <SectionHeader
        icon={MonitorSmartphone}
        title={data?.session.userName ?? data?.session.subjectId ?? 'Session'}
        description="One session, who it belongs to, and how it was authenticated."
        info={
          <>
            No token appears here because none is stored. An access token is verified without a
            database read, so revocation works by ending this record and raising the account&apos;s
            epoch, which retires every token issued before it without listing any of them.
          </>
        }
      />

      {detail.error && <ErrorState message={detail.error} onRetry={() => void detail.reload()} />}

      {detail.loading && !data
        ? <LoadingState label="Reading the session…" />
        : data && (
          <>
            <div className="flex flex-wrap items-center gap-2">
              {data.session.current && (
                <Tooltip text="The session your current token was issued under. Ending it signs you out here.">
                  <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                    this browser
                  </span>
                </Tooltip>
              )}
              <RefreshButton onClick={() => void detail.reload()} busy={detail.loading} />
              <ActionButton
                icon={LogOut}
                label={data.session.current ? 'Sign out here' : 'End session'}
                tone="danger"
                busy={detail.busy === sessionId}
                onClick={() => void terminate()}
              />
            </div>

            <Panel icon={UserRound} title="Owner">
              <Fact
                label="Name"
                value={data.owner.userName
                  ? (
                    <Link href={`/system/identities/${encodeURIComponent(data.owner.subjectId)}`} className="text-[#001E2B] hover:underline">
                      {data.owner.userName}
                    </Link>
                  )
                  : 'not recorded'}
              />
              <Fact label="Subject" value={data.owner.subjectId} />
              <Fact label="Kind" value={data.owner.kind ?? 'not recorded'} />
              <Fact
                label="Account"
                value={typeof data.owner.active === 'boolean'
                  ? <StatusBadge status={data.owner.active ? 'active' : 'inactive'} />
                  : 'not recorded'}
              />
              <Fact label="Lifecycle" value={data.owner.lifecycleState ?? 'not recorded'} />
            </Panel>

            <Panel icon={MonitorSmartphone} title="Session">
              <Fact label="Session id" value={data.session.sessionId} />
              <Fact label="Signed in" value={when(data.session.createdAt)} />
              <Fact label="Last seen" value={when(data.session.lastSeenAt)} />
              <Fact
                label="Ends at"
                value={when(data.session.expiresAt)}
                title="Absolute end, whatever the activity."
              />
              <Fact
                label="Idle timeout"
                value={when(data.session.idleExpiresAt)}
                title="Rolling end, moved forward on use. Whichever comes first ends the session."
              />
              <Fact
                label="Applications"
                value={data.session.applications.length === 0
                  ? 'none holding a token'
                  : data.session.applications.join(', ')}
                title={data.session.clientIds.join(', ') || undefined}
              />
              <Fact
                label="Origin"
                value={data.session.origin?.addressFingerprint || data.session.origin?.deviceFingerprint
                  ? `${data.session.origin.addressFingerprint ?? 'unknown'} / ${data.session.origin.deviceFingerprint ?? 'unknown'}`
                  : 'not recorded'}
                title="A short one-way fingerprint of the address and the user agent. Neither is stored raw."
              />
            </Panel>

            <Panel icon={ShieldCheck} title="Authentication and token control">
              <Fact
                label="Opened for"
                value={data.authentication.establishedForClientName ?? 'not recorded'}
                title={data.authentication.establishedForClientId}
              />
              <Fact
                label="Path"
                value={data.authentication.domainName ?? data.authentication.domainId ?? 'not recorded'}
                title="The authentication domain that established this session."
              />
              <Fact
                label="Assurance"
                value={data.authentication.acr ?? 'not recorded'}
                title="NIST SP 800-63 authenticator assurance, carried as the OIDC acr claim."
              />
              <Fact
                label="Methods"
                value={data.authentication.amr?.join(', ') ?? 'not recorded'}
                title="RFC 8176 authentication method references, carried as the OIDC amr claim."
              />
              <Fact
                label="Credential"
                value={data.authentication.credentialId ?? 'not recorded'}
                title="The factor that authenticated this session."
              />
              <Fact
                label="Authorization request"
                value={data.authentication.ticketId ?? 'not recorded'}
                title="The pending authorization this session came from."
              />
              <Fact
                label="Epoch"
                value={String(data.authentication.epoch)}
                title="Tokens issued below this are retired. Raising it revokes every outstanding token of this account without listing any of them."
              />
              <Fact
                label="Refresh generation"
                value={String(data.authentication.refreshGeneration)}
                title="RFC 9700 rotation with reuse detection. A refresh token presenting a lower generation is treated as theft and ends the session."
              />
            </Panel>

            {!data.authentication.tokensStored && (
              <p className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600">
                <strong className="font-semibold text-gray-700">No token is recorded for this session.</strong>{' '}
                That is the design and not a gap in this page: an access token is a JWT verified
                without a database read, so storing one would keep a redeemable credential at rest and
                put the highest write rate in the system on data the token already carries. Revocation
                works by ending this record and raising the epoch above. Nor would a token be shown
                if it were stored: anyone able to read a session would then be able to use it.
              </p>
            )}
          </>
        )}
    </main>
  );
}

/** One titled group of facts, so the three sections of this page are laid out by one rule. */
function Panel({ icon: Icon, title, children }: {
  icon: typeof UserRound;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
        <Icon size={14} className="text-gray-400" aria-hidden />
        {title}
      </h2>
      <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-3">{children}</dl>
    </section>
  );
}
