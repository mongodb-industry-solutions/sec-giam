'use client';

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Boxes, Plus, Power, Save, Scale, Trash2, X } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Fact } from '../../../../components/Fact';
import { Pagination } from '../../../../components/Pagination';
import { ListToolbar } from '../../../../components/ListToolbar';
import { EmptyState, ErrorState, LoadingState, StatusBadge as CatalogStatusBadge } from '../../../../components/ResultState';
import { ActionButton, Fact as RecordFact, RecordCard } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { Field, INPUT } from '../../roles/parts';
import { EffectBadge, StatusBadge as PolicyStatusBadge } from '../../policies/parts';
import type { PolicySummary } from '../../policies/types';
import { ServerForm } from '../ServerForm';
import { draftFromResponse, draftToRegisterBody } from '../shared';

type PolicyStatusFilter = 'all' | 'active' | 'draft' | 'retired';

interface CatalogResource {
  resourceId: string;
  name: string;
  actions: string[];
  status: string;
  catalogVersion: number;
}

interface ResourceServer {
  resourceId: string;
  name: string;
  kind: string;
  audience?: string;
  catalogVersion: number;
  validationMode?: string;
  status: string;
  registeredAt?: string;
  resources: CatalogResource[];
}

/**
 * One resource, and the policies that actually govern it.
 *
 * What a resource is ALLOWED to have done to it lives in policies, not on the resource itself: a
 * role can only ever check an already-declared `resource:action`, and a policy is what narrows or
 * withholds it further. This screen is the reverse of the policy editor's own resource field: there
 * a policy states which resource it governs, here a resource shows which policies govern it, found
 * the same way the decision engine finds them (`?governs=`, `resourceApplies` on the backend), never
 * a second, approximate idea of what "governs" means.
 */
export default function ResourceDetailPage() {
  const params = useParams<{ resourceId: string }>();
  const resourceId = decodeURIComponent(String(params.resourceId));

  const claims = currentClaims();
  const mayManagePolicies = can(claims, 'policies', 'manage');
  const mayManageResources = can(claims, 'permissions', 'manage');
  const [editing, setEditing] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const readCatalog = useCallback(
    () => callApi<{ resourceServers: ResourceServer[] }>('/resource-servers', { query: { limit: 200 }, subject: 'the resource server catalog' }),
    [],
  );
  const catalog = useConsoleResource(readCatalog, 'The resource server catalog could not be read.');

  const { resource, parentServer } = useMemo(() => {
    for (const server of catalog.data?.resourceServers ?? []) {
      if (server.resourceId === resourceId) {
        return {
          resource: { resourceId: server.resourceId, name: server.name, kind: server.kind, status: server.status, actions: [] as string[], serverName: server.name },
          parentServer: server,
        };
      }
      const child = server.resources.find((entry) => entry.resourceId === resourceId);
      if (child) {
        return {
          resource: { resourceId: child.resourceId, name: child.name, kind: 'object', status: child.status, actions: child.actions, serverName: server.name },
          parentServer: server,
        };
      }
    }
    return { resource: null, parentServer: null };
  }, [catalog.data, resourceId]);

  async function registerServer(draft: ReturnType<typeof draftFromResponse>) {
    setNotice(null);
    const done = await catalog.run(
      `register-${draft.name}`,
      () => callApi(`/resource-servers/${encodeURIComponent(draft.name)}/permissions`, {
        method: 'PUT', body: draftToRegisterBody(draft), subject: 'that resource server',
      }),
      'That resource server could not be registered.',
    );
    if (done) { setNotice(`${draft.name}: registered.`); setEditing(false); }
  }

  const [query, setQuery] = useState('');
  const [status, setStatus] = useState<PolicyStatusFilter>('all');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const readGoverning = useCallback(async () => {
    if (!resource) return { policies: [] as PolicySummary[], total: 0 };
    return callApi<{ policies: PolicySummary[]; total: number }>('/policies', {
      query: {
        governs: resource.name,
        q: query || undefined,
        status: status === 'all' ? undefined : status,
        skip: (page - 1) * limit,
        limit,
      },
      subject: 'the policies that govern this resource',
    });
  }, [resource, query, status, page, limit]);
  const governing = useConsoleResource(readGoverning, 'The policies for this resource could not be read.');

  const readOthers = useCallback(async () => {
    if (!resource) return { policies: [] as PolicySummary[], total: 0 };
    return callApi<{ policies: PolicySummary[]; total: number }>('/policies', {
      query: { limit: 200 },
      subject: 'the policies in this realm',
    });
  }, [resource]);
  const allPolicies = useConsoleResource(readOthers, 'The other policies in this realm could not be read.');

  const [assigning, setAssigning] = useState(false);

  async function toggleStatus(policy: PolicySummary) {
    await governing.run(
      `toggle-${policy.policyId}`,
      () => callApi(`/policies/${encodeURIComponent(policy.policyId)}`, {
        method: 'PATCH', body: { status: policy.status === 'active' ? 'retired' : 'active' }, subject: 'that policy',
      }),
      'That policy could not be switched.',
    );
  }

  async function detach(policy: PolicySummary) {
    if (!resource) return;
    const names = (policy.resource.names ?? []).filter((name) => name !== resource.name);
    if (names.length === 0) {
      if (!window.confirm(
        `${resource.name} is the only resource "${policy.name}" governs. Removing it here would leave the policy `
        + 'governing nothing, so it is removed outright instead. Continue?',
      )) return;
      await governing.run(
        `detach-${policy.policyId}`,
        () => callApi(`/policies/${encodeURIComponent(policy.policyId)}`, { method: 'DELETE', subject: 'that policy' }),
        'That policy could not be removed.',
      );
      return;
    }
    await governing.run(
      `detach-${policy.policyId}`,
      () => callApi(`/policies/${encodeURIComponent(policy.policyId)}`, {
        method: 'PATCH', body: { resource: { names } }, subject: 'that policy',
      }),
      'That policy could not be changed.',
    );
  }

  async function attachExisting(policyId: string) {
    if (!resource) return;
    const target = (allPolicies.data?.policies ?? []).find((policy) => policy.policyId === policyId);
    if (!target) return;

    // `names` and `pattern` are exclusive on a policy: attaching by exact name to one that
    // currently matches by pattern would have to give the pattern up, since it cannot keep
    // matching a shape AND an explicit list at once. Asked outright rather than done quietly,
    // because it can narrow what that policy governs everywhere else it already applied.
    if (target.resource.pattern && !target.resource.names?.length) {
      if (!window.confirm(
        `"${target.name}" currently governs by pattern (${target.resource.pattern}), which may match other resources too. `
        + `Attaching it here replaces that pattern with an exact list of names, starting with just "${resource.name}". Continue?`,
      )) return;
    }

    const names = [...new Set([...(target.resource.names ?? []), resource.name])];
    const done = await governing.run(
      `attach-${policyId}`,
      () => callApi(`/policies/${encodeURIComponent(policyId)}`, { method: 'PATCH', body: { resource: { names } }, subject: 'that policy' }),
      'That policy could not be attached.',
    );
    if (done) setAssigning(false);
  }

  async function createFor(input: { name: string; effect: 'allow' | 'deny'; permissions: string; reason: string }) {
    if (!resource) return;
    const done = await governing.run(
      'create',
      () => callApi('/policies', {
        method: 'POST',
        body: {
          name: input.name,
          effect: input.effect,
          resource: { names: [resource.name] },
          permissions: input.permissions.split(',').map((value) => value.trim()).filter(Boolean),
          ...(input.reason ? { reason: input.reason } : {}),
        },
        subject: 'that policy',
      }),
      'That policy could not be created.',
    );
    if (done) setAssigning(false);
  }

  // Computed from the FULL, unfiltered `allPolicies` fetch rather than the paginated/filtered
  // `governing` list: excluding only what the current search/status/page happens to show would
  // offer a policy that already governs this resource as though it did not, the moment a filter
  // hid it from view. Every OTHER policy is offered, pattern-based ones included: `attachExisting`
  // asks before converting one of those, rather than this list quietly deciding for the caller
  // which policies are worth choosing from.
  const attachable = (allPolicies.data?.policies ?? [])
    .filter((policy) => !(policy.resource.names ?? []).includes(resource?.name ?? ''));

  return (
    <main className="space-y-5">
      <Link href="/system/resources" className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]">
        <ArrowLeft size={13} aria-hidden />
        All resource servers
      </Link>

      <SectionHeader
        icon={Boxes}
        title={resource?.name ?? 'Resource'}
        description="What this resource declares, and which policies actually govern it, found the same way the decision engine finds them."
      />

      {catalog.error && <ErrorState message={catalog.error} onRetry={() => void catalog.reload()} />}
      {catalog.loading && !resource && <LoadingState label="Reading the resource catalog…" />}

      {!catalog.loading && !catalog.error && !resource && (
        <EmptyState icon={Boxes} title="No such resource" description="Nothing in this realm's catalog has this id." />
      )}

      {resource && (
        <>
          {notice && <p className="rounded-lg border border-emerald-100 bg-emerald-50 px-3 py-2 text-xs text-emerald-700">{notice}</p>}

          {editing && parentServer ? (
            <ServerForm
              title={parentServer.name}
              draft={draftFromResponse(parentServer)}
              original={draftFromResponse(parentServer)}
              busy={catalog.busy === `register-${parentServer.name}`}
              onCancel={() => setEditing(false)}
              onSave={(draft) => void registerServer(draft)}
            />
          ) : (
            <section className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <CatalogStatusBadge status={resource.status} />
                  <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                    {resource.kind}
                  </span>
                </div>
                {mayManageResources && (
                  <ActionButton icon={Save} label="Edit" onClick={() => setEditing(true)} />
                )}
              </div>
              <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-3">
                <Fact label="Resource server" value={resource.serverName} mono />
                <Fact label="Declared actions" value={resource.actions.length ? resource.actions.join(', ') : 'none'} mono />
              </dl>
              <p className="mt-2 text-[11px] text-gray-400">
                Editing here opens {resource.kind === 'object' ? 'this resource\'s own server' : 'this server'}'s
                whole catalog: the write replaces it as a block, so every resource type it declares is
                shown together, not only this one.
              </p>
            </section>
          )}

          <section className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="font-semibold text-[#001E2B]">Policies that govern this resource</h2>
                <p className="mt-0.5 text-sm text-gray-500">
                  Every active or retired policy whose resource selector, exact name or pattern, actually matches this one.
                </p>
              </div>
              {mayManagePolicies && !assigning && (
                <ActionButton icon={Plus} label="Assign a policy" tone="primary" onClick={() => { setAssigning(true); void allPolicies.reload(); }} />
              )}
            </div>

            {assigning && (
              <AssignPolicy
                resourceName={resource.name}
                attachable={attachable}
                busy={governing.busy}
                onAttach={attachExisting}
                onCreate={createFor}
                onCancel={() => setAssigning(false)}
              />
            )}

            <ListToolbar
              search={{ value: query, onChange: (next) => { setQuery(next); setPage(1); }, placeholder: 'Search by name' }}
              filter={{
                label: 'Filter by status',
                value: status,
                onChange: (next) => { setStatus(next); setPage(1); },
                options: [
                  { key: 'all', label: 'All' },
                  { key: 'active', label: 'Active' },
                  { key: 'draft', label: 'Draft' },
                  { key: 'retired', label: 'Retired' },
                ],
              }}
            />

            {governing.error && <ErrorState message={governing.error} onRetry={() => void governing.reload()} />}
            {governing.loading && <LoadingState label="Reading the policies that govern this resource…" />}

            {!governing.loading && !governing.error && (governing.data?.policies.length ?? 0) === 0 && (
              <EmptyState
                icon={Scale}
                title="No policy governs this resource yet"
                description="Nothing narrows or withholds access to it beyond whatever roles already grant."
              />
            )}

            {!governing.loading && (governing.data?.policies.length ?? 0) > 0 && (
              <ul className="space-y-3">
                {governing.data!.policies.map((policy) => {
                  const byName = (policy.resource.names ?? []).includes(resource.name);
                  return (
                    <RecordCard
                      key={policy.policyId}
                      title={<Link href={`/system/policies/${encodeURIComponent(policy.policyId)}`} className="hover:underline">{policy.name}</Link>}
                      subtitle={`version ${policy.version}`}
                      badges={<><EffectBadge effect={policy.effect} /><PolicyStatusBadge status={policy.status} /></>}
                      facts={
                        <>
                          <RecordFact label="Governs by" value={byName ? 'exact name' : `pattern: ${policy.resource.pattern}`} />
                          <RecordFact label="In effect" value={policy.inEffect ? 'yes' : 'no'} />
                          <RecordFact label="Last changed" value={when(policy.lastModified)} />
                        </>
                      }
                      actions={mayManagePolicies ? (
                        <>
                          <ActionButton
                            icon={Power}
                            label={policy.status === 'active' ? 'Retire' : 'Activate'}
                            busy={governing.busy === `toggle-${policy.policyId}`}
                            onClick={() => void toggleStatus(policy)}
                          />
                          {byName && (
                            <ActionButton
                              icon={Trash2}
                              tone="danger"
                              label="Remove from here"
                              busy={governing.busy === `detach-${policy.policyId}`}
                              onClick={() => void detach(policy)}
                            />
                          )}
                        </>
                      ) : undefined}
                    />
                  );
                })}
              </ul>
            )}

            {!governing.loading && (governing.data?.total ?? 0) > 0 && (
              <Pagination
                page={page}
                totalPages={Math.max(1, Math.ceil((governing.data?.total ?? 0) / limit))}
                total={governing.data?.total ?? 0}
                limit={limit}
                noun="policies"
                onPageChange={setPage}
                onLimitChange={(next) => { setLimit(next); setPage(1); }}
              />
            )}
          </section>
        </>
      )}
    </main>
  );
}

/**
 * Assigning a policy to a resource, two ways: attach one already governing something else by adding
 * this resource's name to it, or write a new one scoped only to this resource from the start. Kept
 * to `names`-based policies only: attaching to a `pattern` policy would mean editing its regular
 * expression, which is a bigger edit than "assign", and belongs on the policy's own screen.
 */
function AssignPolicy({ resourceName, attachable, busy, onAttach, onCreate, onCancel }: {
  resourceName: string;
  attachable: PolicySummary[];
  busy: string | null;
  onAttach: (policyId: string) => void;
  onCreate: (input: { name: string; effect: 'allow' | 'deny'; permissions: string; reason: string }) => void;
  onCancel: () => void;
}) {
  const [mode, setMode] = useState<'new' | 'existing'>('new');
  const [name, setName] = useState('');
  const [effect, setEffect] = useState<'allow' | 'deny'>('allow');
  const [permissions, setPermissions] = useState('');
  const [reason, setReason] = useState('');
  const [existing, setExisting] = useState('');

  return (
    <div className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-[#001E2B]">Assign a policy to {resourceName}</h3>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="flex gap-2 text-xs">
        <button
          type="button"
          onClick={() => setMode('new')}
          className={`rounded-md border px-2.5 py-1.5 font-medium ${mode === 'new' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-600'}`}
        >
          Write a new one
        </button>
        <button
          type="button"
          onClick={() => setMode('existing')}
          className={`rounded-md border px-2.5 py-1.5 font-medium ${mode === 'existing' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-600'}`}
        >
          Attach an existing one
        </button>
      </div>

      {mode === 'new' ? (
        <form
          onSubmit={(event) => { event.preventDefault(); onCreate({ name, effect, permissions, reason }); }}
          className="space-y-3"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Name" hint="Letters, digits, dot, dash and underscore.">
              <input required value={name} onChange={(e) => setName(e.target.value)} pattern="[a-zA-Z0-9._-]+" className={INPUT} />
            </Field>
            <Field label="Effect">
              <select value={effect} onChange={(e) => setEffect(e.target.value as 'allow' | 'deny')} className={INPUT}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </Field>
          </div>
          <Field label="Permissions" hint="Comma separated, full resource:action strings.">
            <input required value={permissions} onChange={(e) => setPermissions(e.target.value)} className={INPUT} placeholder={`${resourceName}:view`} />
          </Field>
          <Field label="Reason">
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} className={INPUT} />
          </Field>
          <button
            type="submit"
            disabled={busy === 'create' || !name.trim() || !permissions.trim()}
            className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] disabled:opacity-50"
          >
            <Plus size={12} aria-hidden />
            {busy === 'create' ? 'Creating…' : 'Create, scoped to this resource'}
          </button>
        </form>
      ) : (
        <div className="space-y-3">
          {attachable.length === 0 ? (
            <p className="text-sm text-gray-400">No other policy in this realm is free to attach here.</p>
          ) : (
            <>
              <Field label="Policy" hint="A policy already named-resource based gains this resource alongside what it already names. One that matches by pattern instead asks to replace that pattern with this exact name.">
                <select value={existing} onChange={(e) => setExisting(e.target.value)} className={INPUT}>
                  <option value="">choose one</option>
                  {attachable.map((policy) => (
                    <option key={policy.policyId} value={policy.policyId}>
                      {policy.name}{policy.resource.pattern ? ' (currently by pattern)' : ''}
                    </option>
                  ))}
                </select>
              </Field>
              <button
                type="button"
                disabled={!existing || busy === `attach-${existing}`}
                onClick={() => onAttach(existing)}
                className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] disabled:opacity-50"
              >
                <Plus size={12} aria-hidden />
                {busy === `attach-${existing}` ? 'Attaching…' : 'Attach'}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
