'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { Activity, AppWindow, ArrowLeft, Pencil, RefreshCw, ShieldOff, UserMinus, UserPlus } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Fact } from '../../../../components/Fact';
import { SecretOnce } from '../../../../components/SecretOnce';
import { Pagination } from '../../../../components/Pagination';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ApiError, callApi, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import {
  ClientOwner, RegisteredClient, SELF_SERVICE_SCOPES, firstRedirectProblem, linesToUris,
} from '../../../../lib/clients';

/**
 * One registered application: what it is, what it may return to, and its credential.
 *
 * A registration outside the reader's reach is NOT FOUND rather than refused, so this screen shows
 * the same thing for "no such application" and "not yours". That is the authority's answer and it is
 * deliberate: confirming an identifier exists is itself an answer.
 */
export default function ClientDetailPage() {
  const params = useParams<{ clientId: string }>();
  const router = useRouter();
  const clientId = decodeURIComponent(String(params.clientId ?? ''));

  const [client, setClient] = useState<RegisteredClient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rotated, setRotated] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);

  const load = useCallback(async () => {
    if (!clientId) return;
    setLoading(true);
    try {
      setClient(await callApi<RegisteredClient>(`/clients/${encodeURIComponent(clientId)}`, {
        subject: 'that application',
      }));
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That application could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [clientId]);

  useEffect(() => { void load(); }, [load]);

  async function rotate() {
    if (!window.confirm(
      'Issue a new secret? The current one stops working immediately, and there is no overlap window.',
    )) return;
    setBusy(true);
    try {
      const answer = await callApi<RegisteredClient>(`/clients/${encodeURIComponent(clientId)}/rotate-secret`, {
        method: 'POST',
        subject: 'that credential',
      });
      setRotated(answer.client_secret ?? null);
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That credential could not be rotated.');
    } finally {
      setBusy(false);
    }
  }

  async function addOwner(named: { subject_id?: string; user_name?: string }) {
    setBusy(true);
    try {
      setClient(await callApi<RegisteredClient>(`/clients/${encodeURIComponent(clientId)}/owners`, {
        method: 'POST',
        subject: 'that principal',
        body: named,
      }));
      setError(null);
      return true;
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That owner could not be added.');
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function removeOwner(owner: ClientOwner) {
    const self = Boolean(owner.is_caller);
    if (!window.confirm(self
      ? 'Remove yourself as an owner? You lose the ability to read, change, rotate and withdraw this '
        + 'application, and you will be taken back to the list.'
      : `Remove ${owner.display_name || owner.ref} as an owner? They lose all authority over this application.`)) return;

    setBusy(true);
    try {
      const answer = await callApi<RegisteredClient>(
        `/clients/${encodeURIComponent(clientId)}/owners/${encodeURIComponent(owner.ref)}`,
        { method: 'DELETE', subject: 'that owner' },
      );
      // Giving up your own ownership may well have given up your sight of this screen.
      if (self && !answer.owned_by_caller) return router.push('/system/clients');
      setClient(answer);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That owner could not be removed.');
    } finally {
      setBusy(false);
    }
  }

  async function withdraw() {
    if (!window.confirm(
      'Withdraw this application? Its credential stops authenticating immediately. The record is kept, marked withdrawn.',
    )) return;
    setBusy(true);
    try {
      await callApi(`/clients/${encodeURIComponent(clientId)}`, {
        method: 'DELETE',
        subject: 'that application',
      });
      router.push('/system/clients');
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That application could not be withdrawn.');
      setBusy(false);
    }
  }

  return (
    <main className="space-y-5">
      <Link
        href="/system/clients"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All applications
      </Link>

      <SectionHeader
        icon={AppWindow}
        title={client?.client_name || clientId || 'Application'}
        description={client ? `Registered ${when(client.created_at)}` : 'One registered application.'}
        actions={client ? <StatusBadge status={client.status ?? 'unknown'} /> : undefined}
      />

      {rotated && (
        <SecretOnce clientId={clientId} secret={rotated} onDismiss={() => setRotated(null)} />
      )}

      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && <LoadingState label="Reading this application…" />}

      {client && !loading && (
        <>
          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">The registration</h2>
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              <Fact label="Client id" value={client.client_id} mono />
              <Fact label="Kind" value={client.client_type} />
              <Fact label="Application type" value={client.application_type} />
              <Fact label="Client authentication" value={client.token_endpoint_auth_method} mono />
              <Fact label="Proof of possession required" value={client.require_pkce ? 'yes' : 'no'} />
              <Fact label="Owners" value={String((client.owners ?? []).length)} />
              <Fact label="Yours" value={client.owned_by_caller ? 'yes' : 'no'} />
              <Fact label="Last changed" value={when(client.last_modified_at)} />
              {client.logo_uri && <Fact label="Logo" value={client.logo_uri} mono />}
            </dl>

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <Chips
                label="Scopes"
                hint="What this application may ask a person to approve. It can do nothing outside them."
                values={(client.scope ?? '').split(' ').filter(Boolean)}
              />
              <Chips
                label="Grant types"
                hint="The ways this application may obtain a token."
                values={client.grant_types ?? []}
              />
              <Chips
                label="Redirect URIs"
                hint="Compared exactly by the authority, never by prefix. An address not written here is refused."
                values={client.redirect_uris ?? []}
              />
              <Chips
                label="Post sign-out redirect URIs"
                hint="Where a person may be returned after signing out. Compared exactly, like the redirects."
                values={client.post_logout_redirect_uris ?? []}
              />
            </div>
          </section>

          <OwnersPanel
            owners={client.owners ?? []}
            busy={busy}
            onAdd={addOwner}
            onRemove={removeOwner}
          />

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Credential</h2>
                <p className="mt-1 text-sm text-gray-500">
                  The authority stores only a hash of the secret, so it can never be read back. Rotating
                  issues a new one and stops the old one immediately: there is no overlap window,
                  because two live secrets means a compromised one keeps working.
                </p>
              </div>
              <button
                type="button"
                disabled={busy || client.status === 'revoked'}
                onClick={() => void rotate()}
                className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-gray-300 px-2.5 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
              >
                <RefreshCw size={12} aria-hidden />
                Rotate secret
              </button>
            </div>
          </section>

          {editing
            ? (
              <EditForm
                client={client}
                onCancel={() => setEditing(false)}
                onSaved={() => { setEditing(false); void load(); }}
              />
            )
            : (
              <div className="flex flex-wrap items-center gap-2">
                <Tooltip text="Change the name, redirects, scopes and grant types. Never the credential: rotate it separately.">
                  <button
                    type="button"
                    onClick={() => setEditing(true)}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
                  >
                    <Pencil size={12} aria-hidden />
                    Edit application
                  </button>
                </Tooltip>
                <Tooltip text="Revokes and drops the credential immediately. The record is kept, marked withdrawn, and there is no reactivate: this cannot be undone.">
                  <button
                    type="button"
                    disabled={busy || client.status === 'revoked'}
                    onClick={() => void withdraw()}
                    className="inline-flex items-center gap-1.5 rounded-md border border-red-200 px-3 py-2 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                  >
                    <ShieldOff size={12} aria-hidden />
                    Withdraw
                  </button>
                </Tooltip>
              </div>
            )}

          <ActivityPanel clientId={clientId} />
        </>
      )}
    </main>
  );
}

/**
 * Everyone who administers this application.
 *
 * Listed in full rather than counted, because "who else can change this?" is the question a shared
 * registration raises and a number does not answer it. Every owner holds the same authority, so the
 * list is flat: there is no primary owner to mark, only the reader themselves.
 */
function OwnersPanel({ owners, busy, onAdd, onRemove }: {
  owners: ClientOwner[];
  busy: boolean;
  onAdd: (named: { subject_id?: string; user_name?: string }) => Promise<boolean>;
  onRemove: (owner: ClientOwner) => void;
}) {
  const [adding, setAdding] = useState(false);
  const [by, setBy] = useState<'user_name' | 'subject_id'>('user_name');
  const [value, setValue] = useState('');

  const last = owners.length <= 1;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!value.trim()) return;
    if (await onAdd({ [by]: value.trim() })) {
      setValue('');
      setAdding(false);
    }
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Owners</h2>
          <p className="mt-1 text-sm text-gray-500">
            Everyone listed here can read, change, rotate and withdraw this application. There is no
            primary owner, and a registration can never be left with none.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setAdding((open) => !open)}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-gray-300 px-2.5 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          <UserPlus size={12} aria-hidden />
          Add an owner
        </button>
      </div>

      {adding && (
        <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-2 rounded-lg border border-gray-200 bg-gray-50 p-3">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Find by</span>
            <select
              value={by}
              onChange={(event) => setBy(event.target.value as 'user_name' | 'subject_id')}
              className="mt-1 block h-[34px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            >
              <option value="user_name">User name</option>
              <option value="subject_id">Subject id</option>
            </select>
          </label>
          <label className="block">
            <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
              Exactly
              <Tooltip text="An exact match against the directory, never a search. The authority answers the same way whether the principal does not exist or belongs to another realm." />
            </span>
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder={by === 'user_name' ? 'Ada Lovelace' : 'sub-9f21'}
              className="mt-1 block h-[34px] w-60 rounded-lg border border-gray-200 px-2.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>
          <button
            type="submit"
            disabled={busy || !value.trim()}
            className="h-[34px] rounded-lg bg-[#001E2B] px-3 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
          >
            Add
          </button>
          <button
            type="button"
            onClick={() => { setAdding(false); setValue(''); }}
            className="h-[34px] rounded-lg border border-gray-300 bg-white px-3 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
          >
            Cancel
          </button>
        </form>
      )}

      <ul className="mt-3 divide-y divide-gray-100 overflow-hidden rounded-lg border border-gray-200">
        {owners.map((owner) => (
          <li key={`${owner.kind}:${owner.ref}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium text-[#001E2B]">{owner.display_name || owner.ref}</span>
                {owner.is_caller && (
                  <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                    you
                  </span>
                )}
                <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                  {owner.kind}
                </span>
              </div>
              <p className="mt-0.5 truncate font-mono text-xs text-gray-400">{owner.ref}</p>
            </div>
            <button
              type="button"
              disabled={busy || last}
              onClick={() => onRemove(owner)}
              title={last ? 'The last owner cannot be removed. Add another first.' : undefined}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <UserMinus size={12} aria-hidden />
              {owner.is_caller ? 'Remove me' : 'Remove'}
            </button>
          </li>
        ))}
      </ul>

      {last && (
        <p className="mt-2 text-xs text-gray-500">
          This is the only owner. Add another before removing it, or the application would be left with
          nobody able to administer it.
        </p>
      )}
    </section>
  );
}

function Chips({ label, hint, values }: { label: string; hint: string; values: string[] }) {
  return (
    <div className="min-w-0">
      <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
        {label}
        <Tooltip text={hint} />
      </span>
      <div className="mt-1.5 flex flex-wrap gap-1">
        {values.length === 0
          ? <span className="text-sm text-gray-400">none</span>
          : values.map((value) => (
              <span key={value} className="break-all rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[11px] text-gray-600">
                {value}
              </span>
            ))}
      </div>
    </div>
  );
}

/** Only what the authority lets a registration change. The secret has its own route on purpose. */
function EditForm({ client, onCancel, onSaved }: {
  client: RegisteredClient;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(client.client_name ?? '');
  const [redirects, setRedirects] = useState((client.redirect_uris ?? []).join('\n'));
  const [postLogout, setPostLogout] = useState((client.post_logout_redirect_uris ?? []).join('\n'));
  const [scope, setScope] = useState(client.scope ?? '');
  const [logoUri, setLogoUri] = useState(client.logo_uri ?? '');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const redirectUris = linesToUris(redirects);
    const problem = firstRedirectProblem(redirectUris);
    if (problem) return setFailure(problem);
    const logoutUris = linesToUris(postLogout);
    const logoutProblem = firstRedirectProblem(logoutUris);
    if (logoutProblem) return setFailure(logoutProblem);

    setBusy(true);
    try {
      await callApi(`/clients/${encodeURIComponent(client.client_id)}`, {
        method: 'PATCH',
        subject: 'that application',
        body: {
          client_name: name.trim(),
          redirect_uris: redirectUris,
          post_logout_redirect_uris: logoutUris,
          scope: scope.trim(),
          ...(logoUri.trim() ? { logo_uri: logoUri.trim() } : {}),
        },
      });
      onSaved();
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : 'That change could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold text-[#001E2B]">Change registration</h2>

      {failure && <ErrorState message={failure} />}

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Name</span>
        <input
          required
          value={name}
          onChange={(event) => setName(event.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <label className="block">
        <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
          Redirect URIs
          <Tooltip text="Compared exactly, never by prefix. One address per line, written in full. A wildcard is refused, and plain HTTP is accepted only on a loopback address." />
        </span>
        <textarea
          rows={3}
          value={redirects}
          onChange={(event) => setRedirects(event.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Post sign-out redirect URIs</span>
        <textarea
          rows={2}
          value={postLogout}
          onChange={(event) => setPostLogout(event.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Scopes</span>
        <input
          value={scope}
          onChange={(event) => setScope(event.target.value)}
          placeholder={SELF_SERVICE_SCOPES.join(' ')}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
        <span className="mt-1 block text-xs text-gray-500">Space separated.</span>
      </label>

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Logo URI</span>
        <input
          value={logoUri}
          onChange={(event) => setLogoUri(event.target.value)}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}

interface ClientSecurityEvent {
  ts: string;
  action: string;
  outcome: string;
  cause?: string;
  subjectId?: string;
  correlationId?: string;
}

/**
 * The identity trail for this application: who signed in through it, and what changed it.
 *
 * The same read the realm-wide activity screen offers, narrowed to this `clientId` by the API
 * itself rather than filtered in the browser. An oversight caller sees every principal who used it;
 * an ordinary owner sees only what they were themselves a party to, because seeing every user who
 * signed in through an application you merely registered is an oversight permission, not an
 * ownership one.
 */
function ActivityPanel({ clientId }: { clientId: string }) {
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const read = useCallback(
    () => callApi<{ events: ClientSecurityEvent[]; total?: number }>('/security-events', {
      query: { clientId, offset: (page - 1) * limit, limit },
      subject: 'this application\'s activity',
    }),
    [clientId, page, limit],
  );
  const activity = useConsoleResource(read, 'This application\'s activity could not be read.');

  const rows = activity.data?.events ?? [];
  const total = activity.data?.total ?? rows.length;

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
        <Activity size={14} className="text-gray-400" aria-hidden />
        Activity
      </h2>
      <p className="mt-1 text-sm text-gray-500">
        Identity events naming this application: sign-ins through it, and changes made to its
        registration. An application's own business events stay with that application; this is
        identity evidence only.
      </p>

      {activity.error && <div className="mt-3"><ErrorState message={activity.error} onRetry={() => void activity.reload()} /></div>}

      {activity.loading
        ? <div className="mt-3"><LoadingState label="Reading activity…" /></div>
        : rows.length === 0
          ? (
            <div className="mt-3">
              <EmptyState icon={Activity} title="Nothing recorded yet" description="No identity event names this application yet." />
            </div>
          )
          : (
            <>
              <ul className="mt-3 divide-y divide-gray-100 overflow-hidden rounded-lg border border-gray-100">
                {rows.map((event, index) => (
                  <li key={`${event.ts}-${index}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5">
                    <span className="w-40 shrink-0 text-xs text-gray-500">{when(event.ts)}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-[#001E2B]">{event.action}</span>
                    {event.subjectId && <span className="w-40 shrink-0 truncate font-mono text-[10px] text-gray-400">{event.subjectId}</span>}
                    <StatusBadge status={event.outcome} />
                  </li>
                ))}
              </ul>

              <div className="mt-2">
                <Pagination
                  page={page}
                  totalPages={Math.max(1, Math.ceil(total / limit))}
                  total={total}
                  limit={limit}
                  noun="events"
                  onPageChange={setPage}
                  onLimitChange={(next) => { setLimit(next); setPage(1); }}
                />
              </div>
            </>
          )}
    </section>
  );
}
