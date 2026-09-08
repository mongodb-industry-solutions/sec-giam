'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { AppWindow, Plus, Search } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Pagination } from '../../../../components/Pagination';
import { FilterChips } from '../../../../components/FilterChips';
import { SecretOnce } from '../../../../components/SecretOnce';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../../lib/console';
import {
  ClientPage, PRIVILEGED_GRANTS, RegisteredClient, SELF_SERVICE_GRANTS, SELF_SERVICE_SCOPES,
  firstRedirectProblem, linesToUris, ownersLabel,
} from '../../../../lib/clients';
import { usePermissions } from '../../../../lib/profile';

/**
 * The applications registered against this authority.
 *
 * Registering one is self-service and the registration belongs to whoever created it, so this list
 * shows a person their own applications. A caller whose role administers the registry sees every one
 * in the realm instead, and the listing says which of the two it is rather than leaving the reader to
 * guess. The narrowing is the authority's, applied in the query: nothing here filters after the fact.
 */

type StatusFilter = 'all' | 'active' | 'suspended' | 'revoked';
type TypeFilter = 'all' | 'confidential' | 'public';

export default function ClientsPage() {
  const [page, setPage] = useState<ClientPage | null>(null);
  const [status, setStatus] = useState<StatusFilter>('all');
  const [type, setType] = useState<TypeFilter>('all');
  const [term, setTerm] = useState('');
  const [applied, setApplied] = useState('');
  const [pageNumber, setPageNumber] = useState(1);
  const [limit, setLimit] = useState(10);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [creating, setCreating] = useState(false);
  const [minted, setMinted] = useState<RegisteredClient | null>(null);
  const [mayAdminister, setMayAdminister] = useState(false);
  const { permissions } = usePermissions();

  useEffect(() => { setMayAdminister(can(currentClaims(), 'clients', 'manage')); }, [permissions]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPage(await callApi<ClientPage>('/clients', {
        subject: 'the application registry',
        query: {
          status: status === 'all' ? undefined : status,
          type: type === 'all' ? undefined : type,
          q: applied || undefined,
          limit,
          offset: (pageNumber - 1) * limit,
        },
      }));
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'The application registry could not be read.');
    } finally {
      setLoading(false);
    }
  }, [status, type, applied, limit, pageNumber]);

  useEffect(() => { void load(); }, [load]);

  function reset() {
    setPageNumber(1);
  }

  const total = page?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const realmWide = page?.scope === 'all';

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={AppWindow}
        title="Applications"
        description={realmWide
          ? 'Every application registered in this realm.'
          : 'The applications you registered, and the credentials they sign in with.'}
        info={realmWide
          ? 'Your role administers the registry, so this lists every registration in the realm rather than only your own. A secret is shown once when it is created and once when it is rotated, and never again.'
          : 'Anyone can register an application here, and the registration belongs to you: this list shows yours and nobody else\'s. A secret is shown once when it is created and once when it is rotated, and never again.'}
        actions={(
          <button
            type="button"
            onClick={() => setCreating((open) => !open)}
            className="inline-flex items-center gap-1.5 rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
          >
            <Plus size={13} aria-hidden />
            Register an application
          </button>
        )}
      />

      {minted?.client_secret && (
        <SecretOnce
          clientId={minted.client_id}
          secret={minted.client_secret}
          onDismiss={() => setMinted(null)}
        />
      )}

      {creating && (
        <CreateForm
          mayAdminister={mayAdminister}
          onCancel={() => setCreating(false)}
          onCreated={(created) => {
            setMinted(created);
            setCreating(false);
            reset();
            void load();
          }}
        />
      )}

      <div className="flex flex-wrap items-end gap-3">
        <FilterChips
          label="Filter by state"
          value={status}
          onChange={(next) => { setStatus(next); reset(); }}
          options={[
            { key: 'all', label: 'All' },
            { key: 'active', label: 'Active' },
            { key: 'suspended', label: 'Suspended' },
            { key: 'revoked', label: 'Withdrawn' },
          ]}
        />
        <FilterChips
          label="Filter by kind"
          value={type}
          onChange={(next) => { setType(next); reset(); }}
          options={[
            { key: 'all', label: 'Any kind' },
            { key: 'confidential', label: 'Confidential' },
            { key: 'public', label: 'Public' },
          ]}
        />
        <form
          className="flex items-center gap-2"
          onSubmit={(event) => { event.preventDefault(); setApplied(term.trim()); reset(); }}
        >
          <label className="sr-only" htmlFor="client-search">Search by name or identifier</label>
          <div className="relative">
            <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" aria-hidden />
            <input
              id="client-search"
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              placeholder="Name or identifier"
              className="h-[34px] w-56 rounded-lg border border-gray-200 pl-7 pr-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </div>
          <button
            type="submit"
            className="h-[34px] rounded-lg border border-gray-200 bg-white px-3 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
          >
            Search
          </button>
          {applied && (
            <button
              type="button"
              onClick={() => { setTerm(''); setApplied(''); reset(); }}
              className="h-[34px] rounded-lg px-2 text-xs text-gray-500 underline-offset-2 hover:underline"
            >
              Clear
            </button>
          )}
        </form>
      </div>

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading the application registry…" />
        : (page?.clients.length ?? 0) === 0
          ? <EmptyState
              icon={AppWindow}
              title="No applications to show"
              description={applied || status !== 'all' || type !== 'all'
                ? 'Nothing matches these filters. Try widening them.'
                : 'Register an application to get a client id and a secret it can sign in with.'}
            />
          : (
            <>
              <ul className="space-y-3">
                {page!.clients.map((client) => (
                  <li key={client.client_id} className={`rounded-xl border border-gray-200 bg-white p-4 shadow-sm ${client.status === 'revoked' ? 'opacity-70' : ''}`}>
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <Link
                            href={`/system/credentials/applications/${encodeURIComponent(client.client_id)}`}
                            className="font-semibold text-[#001E2B] hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
                          >
                            {client.client_name || client.client_id}
                          </Link>
                          <StatusBadge status={client.status ?? 'unknown'} />
                          {client.client_type && (
                            <Tooltip text="A confidential application holds a secret. A public one cannot keep a secret, so it relies on proof of possession at the token endpoint instead.">
                              <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                                {client.client_type}
                              </span>
                            </Tooltip>
                          )}
                          {realmWide && client.owned_by_caller && (
                            <span className="rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                              yours
                            </span>
                          )}
                        </div>
                        <p className="mt-0.5 font-mono text-xs text-gray-400">{client.client_id}</p>
                        <p className="mt-2 text-xs text-gray-500">
                          Registered {when(client.created_at)}
                          {client.last_modified_at && ` · changed ${when(client.last_modified_at)}`}
                          {(client.owners?.length ?? 0) > 0 && ` · owned by ${ownersLabel(client.owners)}`}
                        </p>
                        <div className="mt-2 flex flex-wrap items-center gap-1">
                          <span className="mr-1 text-[10px] uppercase tracking-wider text-gray-400">Redirects</span>
                          {(client.redirect_uris ?? []).length === 0
                            ? <span className="text-xs text-gray-400">none</span>
                            : (client.redirect_uris ?? []).map((uri) => (
                                <span key={uri} className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-600">
                                  {uri}
                                </span>
                              ))}
                        </div>
                      </div>
                      <Link
                        href={`/system/credentials/applications/${encodeURIComponent(client.client_id)}`}
                        className="shrink-0 rounded-md border border-gray-300 px-2.5 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
                      >
                        Open
                      </Link>
                    </div>
                  </li>
                ))}
              </ul>

              <Pagination
                page={pageNumber}
                totalPages={totalPages}
                total={total}
                limit={limit}
                noun="applications"
                onPageChange={setPageNumber}
                onLimitChange={(next) => { setLimit(next); setPageNumber(1); }}
              />
            </>
          )}
    </main>
  );
}

/**
 * Registering an application.
 *
 * The redirect field carries the rule that surprises people most: the authority compares a redirect
 * exactly, so every address has to be written out and a wildcard is refused rather than expanded.
 */
function CreateForm({ mayAdminister, onCancel, onCreated }: {
  mayAdminister: boolean;
  onCancel: () => void;
  onCreated: (client: RegisteredClient) => void;
}) {
  const [name, setName] = useState('');
  const [redirects, setRedirects] = useState('');
  const [postLogout, setPostLogout] = useState('');
  const [scopes, setScopes] = useState<string[]>(['openid', 'profile']);
  const [grants, setGrants] = useState<string[]>(['authorization_code', 'refresh_token']);
  const [logoUri, setLogoUri] = useState('');
  const [ownerRef, setOwnerRef] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const grantOptions = mayAdminister ? [...SELF_SERVICE_GRANTS, ...PRIVILEGED_GRANTS] : SELF_SERVICE_GRANTS;

  function toggle(list: string[], value: string, set: (next: string[]) => void) {
    set(list.includes(value) ? list.filter((item) => item !== value) : [...list, value]);
  }

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
      const created = await callApi<RegisteredClient>('/clients', {
        method: 'POST',
        subject: 'that application',
        body: {
          client_name: name.trim(),
          redirect_uris: redirectUris,
          post_logout_redirect_uris: logoutUris,
          grant_types: grants,
          scope: scopes.join(' '),
          ...(logoUri.trim() ? { logo_uri: logoUri.trim() } : {}),
          ...(mayAdminister && ownerRef.trim() ? { owner_ref: ownerRef.trim() } : {}),
        },
      });
      onCreated(created);
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : 'That application could not be registered.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold text-[#001E2B]">Register an application</h2>

      {failure && <ErrorState message={failure} />}

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Name</span>
        <input
          required
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="Acme Portal"
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <label className="block">
        <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
          Redirect URIs
          <Tooltip text="Compared exactly, never by prefix. Write every address in full, one per line. A wildcard is refused. Plain HTTP is accepted only on a loopback address, and an address on a host this platform serves from is refused because it would place your application inside an origin people already trust." />
        </span>
        <textarea
          rows={3}
          value={redirects}
          onChange={(event) => setRedirects(event.target.value)}
          placeholder={'https://acme.example/callback\nhttp://localhost:3000/callback'}
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
        <span className="mt-1 block text-xs text-gray-500">
          Matched exactly, one per line. No wildcards, no fragments.
        </span>
      </label>

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Post sign-out redirect URIs</span>
        <textarea
          rows={2}
          value={postLogout}
          onChange={(event) => setPostLogout(event.target.value)}
          placeholder="https://acme.example"
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      <fieldset>
        <legend className="text-[10px] uppercase tracking-wider text-gray-400">Grant types</legend>
        <div className="mt-1.5 flex flex-wrap gap-2">
          {grantOptions.map((grant) => (
            <label key={grant} className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs text-gray-700">
              <input
                type="checkbox"
                checked={grants.includes(grant)}
                onChange={() => toggle(grants, grant, setGrants)}
              />
              <span className="font-mono">{grant}</span>
            </label>
          ))}
        </div>
        {!mayAdminister && (
          <p className="mt-1.5 text-xs text-gray-500">
            Machine-to-machine grants are not available to a self-registered application: they act with
            nobody behind them, so they stay an administrator&apos;s decision.
          </p>
        )}
      </fieldset>

      <fieldset>
        <legend className="text-[10px] uppercase tracking-wider text-gray-400">Scopes</legend>
        <div className="mt-1.5 flex flex-wrap gap-2">
          {SELF_SERVICE_SCOPES.map((scope) => (
            <label key={scope} className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs text-gray-700">
              <input
                type="checkbox"
                checked={scopes.includes(scope)}
                onChange={() => toggle(scopes, scope, setScopes)}
              />
              <span className="font-mono">{scope}</span>
            </label>
          ))}
        </div>
        <p className="mt-1.5 text-xs text-gray-500">
          Sign-in scopes only. An application cannot be given authority its owner does not hold.
        </p>
      </fieldset>

      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Logo URI</span>
        <input
          value={logoUri}
          onChange={(event) => setLogoUri(event.target.value)}
          placeholder="https://acme.example/logo.png"
          className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>

      {mayAdminister && (
        <label className="block">
          <span className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-400">
            Owner reference
            <Tooltip text="An opaque reference to a consuming application's own record, added as an owner alongside you. The authority never resolves it. You stay an owner either way, so the registration is never left with nobody able to administer it." />
          </span>
          <input
            value={ownerRef}
            onChange={(event) => setOwnerRef(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
      )}

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={busy || !name.trim()}
          className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {busy ? 'Registering…' : 'Register'}
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
