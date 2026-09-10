'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Check, Plus, UserX, UsersRound } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Pagination } from '../../../components/Pagination';
import { FilterChips } from '../../../components/FilterChips';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from '../../../components/ResultState';
import { Tooltip } from '../../../components/Tooltip';
import { ApiError, callApi, can, currentClaims, when } from '../../../lib/console';
import { usePermissions } from '../../../lib/profile';
import {
  FilterAttribute, ScimList, ScimUser, extensionOf, primaryEmail, scimFilter, useDomainNames,
} from '../../../lib/identities';

const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

type Scope = 'all' | 'pending';

/**
 * The principal directory, over SCIM.
 *
 * Provisioning says a principal EXISTS; something else says it may operate. A create here does not
 * activate anybody unless the realm auto-approves, which is why a newly provisioned principal shows
 * as pending rather than active, and why no role can be granted from this screen.
 */
export default function IdentitiesPage() {
  return (
    <Suspense fallback={<main className="space-y-5"><p className="text-sm text-gray-400">Reading the principal directory…</p></main>}>
      <IdentitiesInner />
    </Suspense>
  );
}

function IdentitiesInner() {
  // Read once from the address so a link from a domain's own screen still lands pre-filtered, but
  // also offered as an ordinary picker below: arriving only by URL meant the same question asked
  // from this screen directly had no way to be asked at all.
  const searchParams = useSearchParams();
  const [domainId, setDomainId] = useState<string>(() => searchParams.get('domainId') ?? '');
  const [kind, setKind] = useState<string>('');

  const [list, setList] = useState<ScimList | null>(null);
  const [scope, setScope] = useState<Scope>('all');
  const [attribute, setAttribute] = useState<FilterAttribute>('none');
  const [value, setValue] = useState('');
  const [applied, setApplied] = useState<string | undefined>(undefined);
  const [pageNumber, setPageNumber] = useState(1);
  const [limit, setLimit] = useState(20);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [decisionBusy, setDecisionBusy] = useState<string | null>(null);

  usePermissions();
  const mayManage = can(currentClaims(), 'identities', 'manage');
  const domainName = useDomainNames();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setList(await callApi<ScimList>('/scim/v2/Users', {
        subject: 'the principal directory',
        query: {
          filter: applied,
          domainId: domainId || undefined,
          kind: kind || undefined,
          pending: scope === 'pending' ? 'true' : undefined,
          // One-based, per the specification. An off-by-one here silently skips a record per page.
          startIndex: (pageNumber - 1) * limit + 1,
          count: limit,
        },
      }));
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'The principal directory could not be read.');
    } finally {
      setLoading(false);
    }
  }, [applied, domainId, kind, scope, pageNumber, limit]);

  useEffect(() => { void load(); }, [load]);

  /**
   * Approving activates a pending signup; rejecting deprovisions it, the same fate as a suspension
   * that was never approved rather than a fourth lifecycle state invented to say the same thing.
   */
  async function decide(user: ScimUser, decision: 'approve' | 'reject') {
    setDecisionBusy(user.id);
    try {
      if (decision === 'approve') {
        await callApi(`/scim/v2/Users/${encodeURIComponent(user.id)}`, {
          method: 'PATCH',
          subject: 'that principal',
          body: { schemas: [PATCH_SCHEMA], Operations: [{ op: 'replace', value: { active: true } }] },
        });
      } else {
        if (!window.confirm(`Reject ${user.userName}? The account is retired rather than deleted, so the record it left survives.`)) {
          setDecisionBusy(null);
          return;
        }
        await callApi(`/scim/v2/Users/${encodeURIComponent(user.id)}`, { method: 'DELETE', subject: 'that principal' });
      }
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That decision could not be recorded.');
    } finally {
      setDecisionBusy(null);
    }
  }

  const total = list?.totalResults ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={UsersRound}
        title="Principals"
        description="People, services and workloads this authority knows about."
        info="Provisioning says a principal exists; whether it may operate is a separate decision. A principal created here is not activated unless the realm approves new principals automatically, and no authority can be granted from this screen: roles are assigned elsewhere, so a directory sync can never become a way to grant yourself something."
        actions={(
          <Tooltip text="Creates the record only. It is not activated unless this realm auto-approves new principals, and no role can be granted from here.">
            <button
              type="button"
              onClick={() => setCreating((open) => !open)}
              className="inline-flex items-center gap-1.5 rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
            >
              <Plus size={13} aria-hidden />
              Provision a principal
            </button>
          </Tooltip>
        )}
      />

      {creating && (
        <CreateForm
          onCancel={() => setCreating(false)}
          onCreated={() => { setCreating(false); setPageNumber(1); void load(); }}
        />
      )}

      <div className="flex flex-wrap items-end gap-4">
        <Tooltip text="A principal awaiting approval exists but cannot sign in yet: this realm reviews sign-ups rather than approving them automatically.">
          <div className="inline-block">
            <FilterChips
              label="Filter by lifecycle"
              value={scope}
              onChange={(next) => { setScope(next); setPageNumber(1); }}
              options={[{ key: 'all', label: 'All' }, { key: 'pending', label: 'Awaiting approval' }]}
            />
          </div>
        </Tooltip>

        <Tooltip text="The authentication path a principal was provisioned through. Every credential it can sign in with belongs to this path.">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Filter by authentication path</span>
            <select
              value={domainId}
              onChange={(event) => { setDomainId(event.target.value); setPageNumber(1); }}
              className="mt-1 block h-[34px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            >
              <option value="">Every path</option>
              {domainName.domains.map((domain) => (
                <option key={domain.domainId} value={domain.domainId}>{domain.displayName}</option>
              ))}
            </select>
          </label>
        </Tooltip>

        <Tooltip text="What this principal IS, not how it authenticates: a person, a workload, an agent, an application acting as its own credential, or a service.">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Filter by kind</span>
            <select
              value={kind}
              onChange={(event) => { setKind(event.target.value); setPageNumber(1); }}
              className="mt-1 block h-[34px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            >
              <option value="">Every kind</option>
              <option value="human">Person</option>
              <option value="workload">Workload</option>
              <option value="agent">Agent</option>
              <option value="application">Application</option>
              <option value="service">Service</option>
            </select>
          </label>
        </Tooltip>
      </div>

      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setApplied(scimFilter(attribute, value.trim()));
          setPageNumber(1);
        }}
      >
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Filter on</span>
          <select
            value={attribute}
            onChange={(event) => { setAttribute(event.target.value as FilterAttribute); setValue(''); }}
            className="mt-1 block h-[34px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          >
            <option value="none">No filter</option>
            <option value="userName">User name</option>
            <option value="externalId">External id</option>
            <option value="active">Active</option>
          </select>
        </label>

        {attribute === 'active' && (
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Is</span>
            <select
              value={value}
              onChange={(event) => setValue(event.target.value)}
              className="mt-1 block h-[34px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            >
              <option value="">Choose</option>
              <option value="true">Active</option>
              <option value="false">Not active</option>
            </select>
          </label>
        )}

        {(attribute === 'userName' || attribute === 'externalId') && (
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Equals</span>
            <input
              value={value}
              onChange={(event) => setValue(event.target.value)}
              placeholder="Exact value"
              className="mt-1 block h-[34px] w-56 rounded-lg border border-gray-200 px-2.5 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>
        )}

        <button
          type="submit"
          className="h-[34px] rounded-lg border border-gray-200 bg-white px-3 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          Apply
        </button>
        {applied && (
          <button
            type="button"
            onClick={() => { setAttribute('none'); setValue(''); setApplied(undefined); setPageNumber(1); }}
            className="h-[34px] rounded-lg px-2 text-xs text-gray-500 underline-offset-2 hover:underline"
          >
            Clear
          </button>
        )}
        <p className="ml-1 self-center text-xs text-gray-400">
          Only exact matches are supported, and anything else is refused rather than half-interpreted.
        </p>
      </form>

      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {loading
        ? <LoadingState label="Reading the principal directory…" />
        : (list?.Resources.length ?? 0) === 0
          ? <EmptyState
              icon={UsersRound}
              title="No principals to show"
              description={applied
                ? 'Nothing matches this filter. The authority matches exactly, so a partial value finds nothing.'
                : 'No principal is recorded in this realm yet.'}
            />
          : (
            <>
              <ul className="divide-y divide-gray-100 overflow-hidden rounded-xl border border-gray-200 bg-white">
                {list!.Resources.map((user) => {
                  const extension = extensionOf(user);
                  return (
                    <li key={user.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Link
                            href={`/system/identities/${encodeURIComponent(user.id)}`}
                            className="font-medium text-[#001E2B] hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
                          >
                            {user.name?.formatted || user.userName}
                          </Link>
                          <StatusBadge status={extension.lifecycleState || (user.active ? 'active' : 'inactive')} />
                          {extension.kind && (
                            <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                              {extension.kind}
                            </span>
                          )}
                          {extension.domainId && (
                            <Tooltip text="The authentication path this principal was provisioned through. Every credential it can sign in with belongs to this path.">
                              <span className="rounded border border-blue-100 bg-blue-50 px-1.5 py-0.5 text-[10px] font-medium text-blue-700">
                                {domainName.name(extension.domainId) ?? 'unknown path'}
                              </span>
                            </Tooltip>
                          )}
                        </div>
                        <p className="mt-0.5 truncate font-mono text-xs text-gray-400">{user.id}</p>
                      </div>
                      <span className="w-56 shrink-0 truncate text-xs text-gray-500">{primaryEmail(user) || 'no email'}</span>
                      <span className="w-40 shrink-0 text-xs text-gray-400">{when(user.meta?.created)}</span>
                      {mayManage && extension.lifecycleState === 'pending' && (
                        <div className="flex shrink-0 items-center gap-1.5">
                          <Tooltip text="Activates the account. It can sign in immediately afterwards.">
                            <button
                              type="button"
                              disabled={decisionBusy === user.id}
                              onClick={() => void decide(user, 'approve')}
                              className="inline-flex items-center gap-1 rounded-md border border-emerald-200 px-2 py-1 text-[11px] font-medium text-emerald-700 hover:bg-emerald-50 disabled:opacity-50"
                            >
                              <Check size={11} aria-hidden />
                              Approve
                            </button>
                          </Tooltip>
                          <Tooltip text="Retires the request rather than deleting it, so the record it left survives.">
                            <button
                              type="button"
                              disabled={decisionBusy === user.id}
                              onClick={() => void decide(user, 'reject')}
                              className="inline-flex items-center gap-1 rounded-md border border-red-200 px-2 py-1 text-[11px] font-medium text-red-700 hover:bg-red-50 disabled:opacity-50"
                            >
                              <UserX size={11} aria-hidden />
                              Reject
                            </button>
                          </Tooltip>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>

              <Pagination
                page={pageNumber}
                totalPages={totalPages}
                total={total}
                limit={limit}
                noun="principals"
                onPageChange={setPageNumber}
                onLimitChange={(next) => { setLimit(next); setPageNumber(1); }}
              />
            </>
          )}
    </main>
  );
}

/** Provisioning a principal. Never a role, and never an activation the realm did not decide on. */
function CreateForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [userName, setUserName] = useState('');
  const [externalId, setExternalId] = useState('');
  const [given, setGiven] = useState('');
  const [family, setFamily] = useState('');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const formatted = [given.trim(), family.trim()].filter(Boolean).join(' ');
      await callApi('/scim/v2/Users', {
        method: 'POST',
        subject: 'that principal',
        body: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: userName.trim(),
          ...(externalId.trim() ? { externalId: externalId.trim() } : {}),
          ...(formatted
            ? { name: { formatted, ...(given.trim() ? { givenName: given.trim() } : {}), ...(family.trim() ? { familyName: family.trim() } : {}) } }
            : {}),
          ...(email.trim() ? { emails: [{ value: email.trim(), primary: true }] } : {}),
        },
      });
      onCreated();
    } catch (error) {
      setFailure(error instanceof ApiError ? error.message : 'That principal could not be provisioned.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4 rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold text-[#001E2B]">Provision a principal</h2>
      <p className="text-xs text-gray-500">
        Whether the new principal may operate is the realm&apos;s decision, not this form&apos;s. Any
        active flag sent from here is deliberately ignored. Provisioning always lands in this
        realm&apos;s own internal directory; a principal reached through a federated path is created
        by signing in through it, not from here.
      </p>

      {failure && <ErrorState message={failure} />}

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">User name</span>
          <input
            required
            value={userName}
            onChange={(event) => setUserName(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">External id</span>
          <input
            value={externalId}
            onChange={(event) => setExternalId(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Given name</span>
          <input
            value={given}
            onChange={(event) => setGiven(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Family name</span>
          <input
            value={family}
            onChange={(event) => setFamily(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block sm:col-span-2">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Primary email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={busy || !userName.trim()}
          className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {busy ? 'Provisioning…' : 'Provision'}
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
