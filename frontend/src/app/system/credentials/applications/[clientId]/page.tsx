'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  Activity, AppWindow, ArrowLeft, RefreshCw, Save, ShieldOff, UserMinus, UserPlus, UsersRound,
} from 'lucide-react';
import { SectionHeader } from '../../../../../components/SectionHeader';
import { Tooltip } from '../../../../../components/Tooltip';
import { Fact } from '../../../../../components/Fact';
import { SecretOnce } from '../../../../../components/SecretOnce';
import { Pagination } from '../../../../../components/Pagination';
import { UriListEditor } from '../../../../../components/UriListEditor';
import { IntegrationUrls } from '../../../../../components/IntegrationUrls';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../../../components/ResultState';
import { ApiError, callApi, when } from '../../../../../lib/console';
import { storedRealm } from '../../../../../lib/session';
import { useConsoleResource } from '../../../../../lib/useConsoleResource';
import { useConfirm } from '../../../../../components/ConfirmProvider';
import {
  ClientOwner, RegisteredClient, SELF_SERVICE_SCOPES, redirectUriProblem, firstRedirectProblem,
} from '../../../../../lib/clients';

const FIELD_LABEL = 'text-[10px] uppercase tracking-wider text-gray-400';
const FIELD_INPUT = 'mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10';
const FIELD_INPUT_MONO = `${FIELD_INPUT} font-mono text-xs`;

/** Two address lists read the same when they hold the same entries in the same order. */
function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/**
 * One registered application: what it is, what it may return to, and its credential.
 *
 * A registration outside the reader's reach is NOT FOUND rather than refused, so this screen shows
 * the same thing for "no such application" and "not yours". That is the authority's answer and it is
 * deliberate: confirming an identifier exists is itself an answer.
 *
 * View and edit are one screen: the fields below start equal to the loaded registration and stay
 * that way until something is actually typed, `dirty` is what enables Save, and there is no separate
 * mode to enter first. Navigating away with something unsaved asks first, in the browser (a refresh
 * or a closed tab) and on the one in-app link this page itself offers.
 */
export default function ClientDetailPage() {
  const params = useParams<{ clientId: string }>();
  const router = useRouter();
  const confirm = useConfirm();
  const clientId = decodeURIComponent(String(params.clientId ?? ''));

  const [client, setClient] = useState<RegisteredClient | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rotated, setRotated] = useState<string | null>(null);

  // Draft fields, reset to the server's own values whenever `client` changes: once on the first
  // read, and again the moment a save reloads it, so a saved change can never look undone.
  const [name, setName] = useState('');
  const [redirects, setRedirects] = useState<string[]>([]);
  const [postLogout, setPostLogout] = useState<string[]>([]);
  const [scope, setScope] = useState('');
  const [logoUri, setLogoUri] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveFailure, setSaveFailure] = useState<string | null>(null);

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

  useEffect(() => {
    if (!client) return;
    setName(client.client_name ?? '');
    setRedirects(client.redirect_uris ?? []);
    setPostLogout(client.post_logout_redirect_uris ?? []);
    setScope(client.scope ?? '');
    setLogoUri(client.logo_uri ?? '');
    setSaveFailure(null);
  }, [client]);

  const dirty = useMemo(() => {
    if (!client) return false;
    return name !== (client.client_name ?? '')
      || !sameList(redirects, client.redirect_uris ?? [])
      || !sameList(postLogout, client.post_logout_redirect_uris ?? [])
      || scope !== (client.scope ?? '')
      || logoUri !== (client.logo_uri ?? '');
  }, [client, name, redirects, postLogout, scope, logoUri]);

  // Browser-level navigation away: a refresh, a closed tab, a typed URL. `beforeunload` is the only
  // hook for any of the three; the confirmation text itself is no longer shown by any browser still
  // supported here, only the fact that one fires.
  useEffect(() => {
    if (!dirty) return;
    function warn(event: BeforeUnloadEvent) {
      event.preventDefault();
      event.returnValue = '';
    }
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  /** In-app navigation away, for the one link this page itself offers. */
  async function confirmLeave(): Promise<boolean> {
    return !dirty || confirm('Leave without saving? Your changes to this application will be lost.');
  }

  async function save() {
    const redirectUris = redirects.map((uri) => uri.trim()).filter(Boolean);
    const problem = firstRedirectProblem(redirectUris);
    if (problem) { setSaveFailure(problem); return; }
    const logoutUris = postLogout.map((uri) => uri.trim()).filter(Boolean);
    const logoutProblem = firstRedirectProblem(logoutUris);
    if (logoutProblem) { setSaveFailure(logoutProblem); return; }

    setSaving(true);
    try {
      const updated = await callApi<RegisteredClient>(`/clients/${encodeURIComponent(clientId)}`, {
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
      setClient(updated);
      setSaveFailure(null);
    } catch (failure) {
      setSaveFailure(failure instanceof ApiError ? failure.message : 'That change could not be saved.');
    } finally {
      setSaving(false);
    }
  }

  async function rotate() {
    if (!(await confirm(
      'Issue a new secret? The current one stops working immediately, and there is no overlap window.',
    ))) return;
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
    if (!(await confirm(self
      ? 'Remove yourself as an owner? You lose the ability to read, change, rotate and withdraw this '
        + 'application, and you will be taken back to the list.'
      : `Remove ${owner.display_name || owner.ref} as an owner? They lose all authority over this application.`))) return;

    setBusy(true);
    try {
      const answer = await callApi<RegisteredClient>(
        `/clients/${encodeURIComponent(clientId)}/owners/${encodeURIComponent(owner.ref)}`,
        { method: 'DELETE', subject: 'that owner' },
      );
      // Giving up your own ownership may well have given up your sight of this screen.
      if (self && !answer.owned_by_caller) return router.push('/system/credentials/applications');
      setClient(answer);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That owner could not be removed.');
    } finally {
      setBusy(false);
    }
  }

  async function withdraw() {
    if (!(await confirm(
      'Withdraw this application? Its credential stops authenticating immediately. The record is kept, marked withdrawn.',
    ))) return;
    setBusy(true);
    try {
      await callApi(`/clients/${encodeURIComponent(clientId)}`, {
        method: 'DELETE',
        subject: 'that application',
      });
      router.push('/system/credentials/applications');
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That application could not be withdrawn.');
      setBusy(false);
    }
  }

  return (
    <main className="space-y-5">
      <Link
        href="/system/credentials/applications"
        onClick={(event) => {
          event.preventDefault();
          void confirmLeave().then((leave) => { if (leave) router.push('/system/credentials/applications'); });
        }}
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All applications
      </Link>

      <SectionHeader
        icon={AppWindow}
        title={client ? (name || client.client_name) : clientId || 'Application'}
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
            </dl>

            {saveFailure && <div className="mt-3"><ErrorState message={saveFailure} /></div>}

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className={FIELD_LABEL}>Name</span>
                <input required value={name} onChange={(event) => setName(event.target.value)} className={FIELD_INPUT} />
              </label>
              <label className="block">
                <span className={FIELD_LABEL}>Logo URI</span>
                <input value={logoUri} onChange={(event) => setLogoUri(event.target.value)} className={FIELD_INPUT_MONO} />
              </label>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <div>
                <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
                  Redirect URIs
                  <Tooltip text="Compared exactly, never by prefix. Written in full, one address per row. A wildcard is refused, and plain HTTP is accepted only on a loopback address." />
                </span>
                <div className="mt-1">
                  <UriListEditor
                    values={redirects}
                    onChange={setRedirects}
                    placeholder="https://app.example/callback"
                    problemFor={redirectUriProblem}
                  />
                </div>
              </div>
              <div>
                <span className={FIELD_LABEL}>Post sign-out redirect URIs</span>
                <div className="mt-1">
                  <UriListEditor
                    values={postLogout}
                    onChange={setPostLogout}
                    placeholder="https://app.example/signed-out"
                    problemFor={redirectUriProblem}
                  />
                </div>
              </div>
            </div>

            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className={FIELD_LABEL}>Scopes</span>
                <input
                  value={scope}
                  onChange={(event) => setScope(event.target.value)}
                  placeholder={SELF_SERVICE_SCOPES.join(' ')}
                  className={FIELD_INPUT_MONO}
                />
                <span className="mt-1 block text-xs text-gray-500">
                  Space separated. What this application may ask a person to approve; it can do
                  nothing outside them.
                </span>
              </label>
              <Chips
                label="Grant types"
                hint="The ways this application may obtain a token."
                values={client.grant_types ?? []}
              />
            </div>
          </section>

          <IntegrationUrls realm={storedRealm()} grantTypes={client.grant_types ?? []} />

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

          <div className="flex flex-wrap items-center gap-2">
            <Tooltip text="Change the name, redirects, scopes and grant types. Never the credential: rotate it separately.">
              <button
                type="button"
                disabled={!dirty || saving}
                onClick={() => void save()}
                className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
              >
                <Save size={12} aria-hidden />
                {saving ? 'Saving…' : 'Save'}
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

          <AuthorizedPrincipals clientId={clientId} />
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
                {owner.kind === 'principal'
                  ? (
                    <Link
                      href={`/system/identities/${encodeURIComponent(owner.ref)}`}
                      className="font-medium text-[#001E2B] hover:underline"
                    >
                      {owner.display_name || owner.ref}
                    </Link>
                  )
                  : <span className="font-medium text-[#001E2B]">{owner.display_name || owner.ref}</span>}
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

interface ApplicationGrant {
  grantId: string;
  subjectId: string;
  subjectName?: string;
  status: 'active' | 'revoked';
  grantedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
}

/**
 * Everyone who has authorised this application, the reverse of the account owner's own
 * `/system/applications`: not "what did I allow", but "who allowed this".
 *
 * An oversight query the API itself gates on `grants:view`, same as the activity panel below it. The
 * grant is withdrawn the same way an owner withdraws their own, `DELETE /grants/:grantId`, naming
 * `subjectId` so the authority resolves it as somebody else's rather than the caller's.
 */
function AuthorizedPrincipals({ clientId }: { clientId: string }) {
  const confirm = useConfirm();
  const read = useCallback(
    () => callApi<{ grants: ApplicationGrant[] }>('/grants', {
      query: { clientId, status: 'all' },
      subject: 'who has authorized this application',
    }),
    [clientId],
  );
  const grants = useConsoleResource(read, 'Who has authorized this application could not be read.');
  const rows = grants.data?.grants ?? [];

  async function withdraw(grant: ApplicationGrant) {
    if (!(await confirm(`Withdraw ${grant.subjectName ?? grant.subjectId}'s authorization of this application?`))) return;
    await grants.run(grant.grantId, () => callApi(`/grants/${encodeURIComponent(grant.grantId)}`, {
      method: 'DELETE',
      query: { subjectId: grant.subjectId },
      subject: 'that authorization',
    }), 'That authorization could not be withdrawn.');
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
        <UsersRound size={14} className="text-gray-400" aria-hidden />
        Who has authorized this application
      </h2>
      <p className="mt-1 text-sm text-gray-500">
        Every principal who has allowed this application to act on their behalf, and when.
      </p>

      {grants.error && <div className="mt-3"><ErrorState message={grants.error} onRetry={() => void grants.reload()} /></div>}

      {grants.loading
        ? <div className="mt-3"><LoadingState label="Reading who authorized this application…" /></div>
        : rows.length === 0
          ? (
            <div className="mt-3">
              <EmptyState icon={UsersRound} title="Nobody yet" description="No principal has authorized this application yet." />
            </div>
          )
          : (
            <ul className="mt-3 space-y-2">
              {rows.map((grant) => (
                <li
                  key={grant.grantId}
                  className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm ${
                    grant.status === 'active' ? 'border-gray-200' : 'border-gray-100 bg-gray-50 text-gray-400'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/system/identities/${encodeURIComponent(grant.subjectId)}`}
                        className="font-medium text-[#001E2B] hover:underline"
                      >
                        {grant.subjectName ?? grant.subjectId}
                      </Link>
                      <StatusBadge status={grant.status} />
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">
                      Authorized {when(grant.grantedAt)}
                      {grant.revokedAt && ` · withdrawn ${when(grant.revokedAt)}`}
                      {grant.lastUsedAt && ` · last used ${when(grant.lastUsedAt)}`}
                    </p>
                  </div>
                  {grant.status === 'active' && (
                    <button
                      type="button"
                      disabled={grants.busy === grant.grantId}
                      onClick={() => void withdraw(grant)}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-50"
                    >
                      <ShieldOff size={12} aria-hidden />
                      Withdraw
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
    </section>
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
