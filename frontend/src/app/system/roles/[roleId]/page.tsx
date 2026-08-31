'use client';

import { useCallback, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Check, Minus, Plus, Save, ShieldHalf, Trash2, UserMinus, UserPlus } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { EmptyState, ErrorState, LoadingState } from '../../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { BuiltinBadge, Field, INPUT, ScopeBadge } from '../parts';
import type { Assignment, CatalogPermission, ResolvedPermission, RoleDetail, RoleSummary } from '../types';

/**
 * One role: what it grants, where each permission comes from, and who holds it.
 *
 * The permission matrix is the point of the screen. A role's authority read as a list of
 * `resource:action` strings is a wall nobody checks; read as a grid of resources against actions it
 * is something a reviewer can scan and notice a gap in. Inherited cells are marked rather than
 * merged away, because "this role grants it" and "a parent grants it" are different findings.
 */

export default function RoleDetailPage() {
  const params = useParams<{ roleId: string }>();
  const router = useRouter();
  const roleId = decodeURIComponent(String(params.roleId));

  const claims = currentClaims();
  const mayManageRoles = can(claims, 'roles', 'manage');
  const mayViewAssignments = can(claims, 'assignments', 'view');
  const mayManageAssignments = can(claims, 'assignments', 'manage');
  const mayReadCatalog = can(claims, 'permissions', 'view');

  const read = useCallback(
    () => callApi<RoleDetail>(`/roles/${encodeURIComponent(roleId)}`, { subject: 'that role' }),
    [roleId],
  );
  const role = useConsoleResource(read, 'That role could not be read.');

  const [editing, setEditing] = useState(false);

  async function remove() {
    if (!window.confirm('Remove this role? It is refused while anything still depends on it.')) return;
    const done = await role.run(
      'delete',
      () => callApi(`/roles/${encodeURIComponent(roleId)}`, { method: 'DELETE', subject: 'that role' }),
      'That role could not be removed.',
    );
    if (done) router.push('/system/roles');
  }

  async function save(patch: Record<string, unknown>) {
    const done = await role.run(
      'save',
      () => callApi(`/roles/${encodeURIComponent(roleId)}`, { method: 'PATCH', body: patch, subject: 'that role' }),
      'That role could not be changed.',
    );
    if (done) setEditing(false);
  }

  const detail = role.data;

  return (
    <main className="space-y-5">
      <Link href="/system/roles" className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]">
        <ArrowLeft size={13} aria-hidden />
        All roles
      </Link>

      <SectionHeader
        icon={ShieldHalf}
        title={detail?.displayName ?? 'Role'}
        description={detail?.description || 'What this role grants, and who holds it.'}
        actions={detail && mayManageRoles
          ? (
            <div className="flex gap-2">
              <ActionButton
                icon={Save}
                label={editing ? 'Stop editing' : 'Edit'}
                onClick={() => setEditing((was) => !was)}
              />
              <ActionButton
                icon={Trash2}
                label="Remove"
                tone="danger"
                busy={role.busy === 'delete'}
                disabled={detail.builtin}
                onClick={() => void remove()}
              />
            </div>
          )
          : undefined}
      />

      {role.error && <ErrorState message={role.error} onRetry={() => void role.reload()} />}

      {role.loading && !detail
        ? <LoadingState label="Reading the role…" />
        : !detail
          ? null
          : (
            <>
              <section className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-gray-400">{detail.name}</span>
                  <ScopeBadge scopeKind={detail.scopeKind} />
                  {detail.builtin && <BuiltinBadge />}
                </div>
                <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-4">
                  <Fact label="States" value={`${detail.ownPermissionCount} permissions`} />
                  <Fact label="Grants in total" value={`${detail.effectivePermissionCount} permissions`} />
                  <Fact label="Held by" value={`${detail.assignmentCount} principal${detail.assignmentCount === 1 ? '' : 's'}`} />
                  <Fact label="Last changed" value={when(detail.lastModified)} />
                </dl>

                {detail.parents.length > 0 && (
                  <p className="mt-3 text-sm text-gray-600">
                    Inherits from{' '}
                    {detail.parents.map((parent, index) => (
                      <span key={parent.roleId}>
                        {index > 0 && ', '}
                        <Link href={`/system/roles/${encodeURIComponent(parent.roleId)}`} className="font-medium text-[#001E2B] hover:underline">
                          {parent.displayName}
                        </Link>
                      </span>
                    ))}
                    .
                  </p>
                )}

                {detail.sodRationale && (
                  <p className="mt-3 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">
                    {detail.sodRationale}
                  </p>
                )}
              </section>

              {editing && mayManageRoles && (
                <EditRole detail={detail} busy={role.busy === 'save'} onSave={save} onCancel={() => setEditing(false)} />
              )}

              <PermissionMatrix permissions={detail.effectivePermissions} roleName={detail.name} />

              {detail.denialRationale && detail.denialRationale.length > 0 && (
                <section className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                  <h2 className="font-semibold text-[#001E2B]">What it deliberately withholds</h2>
                  <p className="mt-0.5 text-sm text-gray-500">
                    Recorded as data rather than left as a comment, because an absence with no reason
                    reads as an oversight.
                  </p>
                  <ul className="mt-3 space-y-2 text-sm">
                    {detail.denialRationale.map((denial) => (
                      <li key={`${denial.resource}:${denial.action ?? '*'}`} className="border-l-2 border-red-200 pl-2.5">
                        <span className="font-mono text-xs text-gray-500">
                          {denial.resource}{denial.action ? `:${denial.action}` : ''}
                        </span>
                        <p className="text-gray-600">{denial.reason}</p>
                      </li>
                    ))}
                  </ul>
                </section>
              )}

              {mayReadCatalog && mayManageRoles && editing && <CatalogHint />}

              {mayViewAssignments && (
                <Assignments roleId={roleId} mayManage={mayManageAssignments} onChanged={() => void role.reload()} />
              )}
            </>
          )}
    </main>
  );
}

/**
 * The permission matrix: resources down, actions across.
 *
 * A grid rather than a list because the question a reviewer actually has is comparative. "Can this
 * role manage what it can view" is answerable at a glance here and only by careful reading in a
 * list, and the second one is the format that lets a mistake survive review.
 */
function PermissionMatrix({ permissions, roleName }: { permissions: ResolvedPermission[]; roleName: string }) {
  const { actions, resources, cells } = useMemo(() => {
    const actionSet = new Set<string>();
    const resourceMap = new Map<string, { server: string }>();
    const cellMap = new Map<string, ResolvedPermission>();
    for (const permission of permissions) {
      actionSet.add(permission.action);
      resourceMap.set(permission.resource, { server: permission.resourceServer });
      cellMap.set(`${permission.resource}:${permission.action}`, permission);
    }
    return {
      actions: [...actionSet].sort(),
      resources: [...resourceMap.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      cells: cellMap,
    };
  }, [permissions]);

  if (permissions.length === 0) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title="This role grants nothing"
        description="No permission is written on it and it inherits none. A principal holding it gains no authority."
      />
    );
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white shadow-sm">
      <div className="border-b border-gray-100 p-4">
        <h2 className="font-semibold text-[#001E2B]">What it grants</h2>
        <p className="mt-0.5 text-sm text-gray-500">
          Everything the role grants once its parents are resolved. A cell marked as inherited comes
          from a parent, so removing it means editing that role rather than this one.
        </p>
      </div>

      {/* The table scrolls rather than the page widening: the gutters are the layout's to set. */}
      <div className="overflow-x-auto">
        <table className="w-full min-w-max text-sm">
          <thead>
            <tr className="border-b border-gray-100 text-left">
              <th scope="col" className="px-4 py-2 text-[10px] font-semibold uppercase tracking-wider text-gray-400">Resource</th>
              {actions.map((action) => (
                <th key={action} scope="col" className="px-3 py-2 text-center text-[10px] font-semibold uppercase tracking-wider text-gray-400">
                  {action}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {resources.map(([resource, { server }]) => (
              <tr key={resource} className="border-b border-gray-50 last:border-0">
                <th scope="row" className="whitespace-nowrap px-4 py-2 text-left font-medium text-[#001E2B]">
                  {resource}
                  <span className="ml-2 font-mono text-[10px] font-normal text-gray-400">{server}</span>
                </th>
                {actions.map((action) => {
                  const cell = cells.get(`${resource}:${action}`);
                  return (
                    <td key={action} className="px-3 py-2 text-center">
                      {!cell
                        ? <Minus size={13} className="mx-auto text-gray-200" aria-label="not granted" />
                        : (
                          <Tooltip text={
                            cell.unenforced
                              ? `Granted through ${cell.via}, but no resource server declares it, so nothing checks it.`
                              : cell.inherited
                                ? `Inherited from ${cell.via}. Removing it means editing that role.`
                                : `Granted directly by ${roleName}.`
                          }>
                            <span className={`inline-flex h-5 w-5 items-center justify-center rounded-full ${
                              cell.unenforced
                                ? 'bg-amber-100 text-amber-700'
                                : cell.inherited
                                  ? 'bg-gray-100 text-gray-500'
                                  : 'bg-emerald-100 text-emerald-700'
                            }`}>
                              <Check size={12} aria-label={cell.inherited ? 'granted, inherited' : 'granted'} />
                            </span>
                          </Tooltip>
                        )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex flex-wrap gap-4 border-t border-gray-100 px-4 py-2.5 text-[11px] text-gray-500">
        <Legend className="bg-emerald-100 text-emerald-700" label="granted by this role" />
        <Legend className="bg-gray-100 text-gray-500" label="inherited from a parent" />
        <Legend className="bg-amber-100 text-amber-700" label="nothing enforces it" />
      </div>
    </section>
  );
}

function Legend({ className, label }: { className: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`inline-flex h-4 w-4 items-center justify-center rounded-full ${className}`}>
        <Check size={10} aria-hidden />
      </span>
      {label}
    </span>
  );
}

/**
 * Editing what a role states.
 *
 * The permission list is replaced rather than merged, which is why the whole set is presented as
 * checkboxes against the realm's catalog: a form that could only add would make removing a
 * permission impossible from here, and the API says the same thing.
 */
function EditRole({ detail, busy, onSave, onCancel }: {
  detail: RoleDetail;
  busy: boolean;
  onSave: (patch: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const [displayName, setDisplayName] = useState(detail.displayName);
  const [description, setDescription] = useState(detail.description);
  const [scopeKind, setScopeKind] = useState(detail.scopeKind);
  const [held, setHeld] = useState<Set<string>>(
    () => new Set(detail.ownPermissions.map((permission) => `${permission.resource}:${permission.action}`)),
  );
  const [parents, setParents] = useState<string[]>(detail.parentRoleIds);

  const readCatalog = useCallback(
    () => callApi<{ permissions: CatalogPermission[] }>('/permissions', { subject: 'the permission catalog' }),
    [],
  );
  const catalog = useConsoleResource(readCatalog, 'The permission catalog could not be read.');

  const readRoles = useCallback(
    () => callApi<{ roles: RoleSummary[] }>('/roles', { query: { limit: 200 }, subject: 'the roles in this realm' }),
    [],
  );
  const allRoles = useConsoleResource(readRoles, 'The roles could not be read.');

  const grouped = useMemo(() => {
    const map = new Map<string, CatalogPermission[]>();
    for (const permission of catalog.data?.permissions ?? []) {
      if (permission.deprecated) continue;
      const list = map.get(permission.resource) ?? [];
      list.push(permission);
      map.set(permission.resource, list);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [catalog.data]);

  function toggle(key: string) {
    setHeld((was) => {
      const next = new Set(was);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSave({
          displayName,
          description,
          scopeKind,
          parentRoleIds: parents,
          permissions: [...held].map((key) => {
            const [resource, action] = key.split(':');
            return { resource, action };
          }),
        });
      }}
      className="space-y-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <h2 className="font-semibold text-[#001E2B]">Edit this role</h2>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Display name">
          <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
        </Field>
        <Field label="Scope" hint="Realm wide is what makes a role administrative.">
          <select value={scopeKind} onChange={(e) => setScopeKind(e.target.value as 'self' | 'all')} className={INPUT}>
            <option value="self">Own records only</option>
            <option value="all">Realm wide</option>
          </select>
        </Field>
      </div>

      <Field label="Description">
        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className={INPUT} />
      </Field>

      <Field label="Inherits from" hint="A composition that would loop is refused rather than truncated.">
        <select
          multiple
          value={parents}
          onChange={(e) => setParents([...e.target.selectedOptions].map((option) => option.value))}
          className={`${INPUT} h-28`}
        >
          {(allRoles.data?.roles ?? [])
            .filter((candidate) => candidate.roleId !== detail.roleId)
            .map((candidate) => (
              <option key={candidate.roleId} value={candidate.roleId}>{candidate.displayName}</option>
            ))}
        </select>
      </Field>

      <fieldset>
        <legend className="text-xs font-medium text-gray-600">Permissions this role states</legend>
        <p className="mt-0.5 text-[11px] text-gray-400">
          Only what the realm&apos;s resource servers have registered. Inherited permissions are not
          listed here, because they belong to the parent that grants them.
        </p>
        {catalog.loading
          ? <LoadingState label="Reading the permission catalog…" />
          : catalog.error
            ? <ErrorState message={catalog.error} onRetry={() => void catalog.reload()} />
            : (
              <div className="mt-2 max-h-72 space-y-3 overflow-y-auto rounded-lg border border-gray-100 p-3">
                {grouped.map(([resource, permissions]) => (
                  <div key={resource}>
                    <p className="text-xs font-medium text-[#001E2B]">
                      {resource}
                      <span className="ml-2 font-mono text-[10px] font-normal text-gray-400">{permissions[0].resourceServer}</span>
                    </p>
                    <div className="mt-1 flex flex-wrap gap-3">
                      {permissions.map((permission) => {
                        const key = `${permission.resource}:${permission.action}`;
                        return (
                          <label key={key} className="inline-flex items-center gap-1.5 text-xs text-gray-600">
                            <input type="checkbox" checked={held.has(key)} onChange={() => toggle(key)} className="rounded border-gray-300" />
                            {permission.action}
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
      </fieldset>

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Saving…' : 'Save changes'}
        </button>
        <ActionButton icon={Minus} label="Cancel" onClick={onCancel} />
      </div>
    </form>
  );
}

function CatalogHint() {
  return (
    <p className="text-xs text-gray-400">
      A permission appears in the list above only once the application that enforces it has registered
      its catalog with this authority.
    </p>
  );
}

/** Who holds the role, and granting or revoking it. A role screen that cannot answer this is half a screen. */
function Assignments({ roleId, mayManage, onChanged }: {
  roleId: string;
  mayManage: boolean;
  onChanged: () => void;
}) {
  const read = useCallback(
    () => callApi<{ assignments: Assignment[] }>(`/roles/${encodeURIComponent(roleId)}/assignments`, {
      subject: 'who holds this role',
    }),
    [roleId],
  );
  const assignments = useConsoleResource(read, 'The holders of this role could not be read.');
  const [granting, setGranting] = useState(false);
  const [subjectId, setSubjectId] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [justification, setJustification] = useState('');

  async function grant() {
    const done = await assignments.run(
      'grant',
      () => callApi(`/roles/${encodeURIComponent(roleId)}/assignments`, {
        method: 'POST',
        body: {
          subjectId,
          ...(expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {}),
          ...(justification ? { justification } : {}),
        },
        subject: 'that assignment',
      }),
      'That role could not be granted.',
    );
    if (done) {
      setGranting(false);
      setSubjectId('');
      setExpiresAt('');
      setJustification('');
      onChanged();
    }
  }

  async function revoke(assignment: Assignment) {
    if (!window.confirm('Take this role back? The holder loses it at their next token.')) return;
    const done = await assignments.run(
      assignment.assignmentId,
      () => callApi(`/role-assignments/${encodeURIComponent(assignment.assignmentId)}`, {
        method: 'DELETE',
        subject: 'that assignment',
      }),
      'That assignment could not be revoked.',
    );
    if (done) onChanged();
  }

  const rows = assignments.data?.assignments ?? [];

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="font-semibold text-[#001E2B]">Who holds this role</h2>
          <p className="mt-0.5 text-sm text-gray-500">
            Lapsed assignments stay on the list: what somebody used to hold, and until when, is the
            question asked after something goes wrong.
          </p>
        </div>
        {mayManage && !granting && (
          <ActionButton icon={UserPlus} label="Grant to a principal" onClick={() => setGranting(true)} />
        )}
      </div>

      {granting && mayManage && (
        <form
          onSubmit={(event) => { event.preventDefault(); void grant(); }}
          className="space-y-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
        >
          <Field label="Principal" hint="The subject identifier of the principal receiving the role.">
            <input required value={subjectId} onChange={(e) => setSubjectId(e.target.value)} className={INPUT} />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Expires" hint="Leave empty for a standing grant. An expiry makes it a time-bound elevation.">
              <input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className={INPUT} />
            </Field>
            <Field label="Reason" hint="Optional, and the only record of why once the moment has passed.">
              <input value={justification} onChange={(e) => setJustification(e.target.value)} className={INPUT} />
            </Field>
          </div>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={assignments.busy === 'grant' || !subjectId}
              className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
            >
              <Plus size={12} aria-hidden />
              {assignments.busy === 'grant' ? 'Granting…' : 'Grant'}
            </button>
            <ActionButton icon={Minus} label="Cancel" onClick={() => setGranting(false)} />
          </div>
        </form>
      )}

      {assignments.error && <ErrorState message={assignments.error} onRetry={() => void assignments.reload()} />}

      {assignments.loading
        ? <LoadingState label="Reading who holds this role…" />
        : rows.length === 0
          ? <EmptyState title="Nobody holds this role" description="It grants nothing to anyone until it is assigned." />
          : (
            <ul className="space-y-3">
              {rows.map((assignment) => (
                <RecordCard
                  key={assignment.assignmentId}
                  title={assignment.subjectId}
                  subtitle={assignment.assignmentId}
                  badges={
                    <>
                      {!assignment.live && (
                        <span className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-700">
                          lapsed
                        </span>
                      )}
                      {assignment.ephemeral && (
                        <Tooltip text="Time bound. Nothing about it survives the expiry.">
                          <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                            temporary
                          </span>
                        </Tooltip>
                      )}
                    </>
                  }
                  facts={
                    <>
                      <Fact label="Granted" value={when(assignment.grantedAt)} />
                      <Fact label="Granted by" value={assignment.grantedBy ?? 'setup'} />
                      <Fact label="Expires" value={when(assignment.expiresAt)} />
                    </>
                  }
                  actions={mayManage
                    ? (
                      <ActionButton
                        icon={UserMinus}
                        label="Revoke"
                        tone="danger"
                        busy={assignments.busy === assignment.assignmentId}
                        onClick={() => void revoke(assignment)}
                      />
                    )
                    : undefined}
                >
                  {assignment.justification && (
                    <p className="mt-2 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">
                      {assignment.justification}
                    </p>
                  )}
                </RecordCard>
              ))}
            </ul>
          )}
    </section>
  );
}
