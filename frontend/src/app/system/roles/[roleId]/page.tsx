'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Check, Minus, Plus, Power, Save, ShieldHalf, Trash2, UserMinus, UserPlus } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Pagination } from '../../../../components/Pagination';
import { ListToolbar } from '../../../../components/ListToolbar';
import { EmptyState, ErrorState, LoadingState } from '../../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { useConfirm } from '../../../../components/ConfirmProvider';
import { BuiltinBadge, DisabledBadge, Field, INPUT, ScopeBadge } from '../parts';
import type { Assignment, CatalogPermission, ResolvedPermission, RoleDetail, RoleSummary } from '../types';

/**
 * One role: what it grants, where each permission comes from, and who holds it.
 *
 * The permission matrix is the point of the screen. A role's authority read as a list of
 * `resource:action` strings is a wall nobody checks; read as a grid of resources against actions it
 * is something a reviewer can scan and notice a gap in. Inherited cells are marked rather than
 * merged away, because "this role grants it" and "a parent grants it" are different findings.
 *
 * View and edit are ONE screen, not two. The draft fields below start equal to the server's own
 * values and stay that way until something is actually typed or a cell is actually clicked; Save
 * reflects that with `dirty`, rather than existing as a mode a manager has to remember to enter.
 */

export default function RoleDetailPage() {
  const params = useParams<{ roleId: string }>();
  const router = useRouter();
  const confirm = useConfirm();
  const roleId = decodeURIComponent(String(params.roleId));

  const claims = currentClaims();
  const mayManageRoles = can(claims, 'roles', 'manage');
  const mayViewAssignments = can(claims, 'assignments', 'view');
  const mayManageAssignments = can(claims, 'assignments', 'manage');
  const mayReadCatalog = can(claims, 'permissions', 'view');
  const mayManagePermissions = can(claims, 'permissions', 'manage');

  const read = useCallback(
    () => callApi<RoleDetail>(`/roles/${encodeURIComponent(roleId)}`, { subject: 'that role' }),
    [roleId],
  );
  const role = useConsoleResource(read, 'That role could not be read.');
  const detail = role.data;

  // Draft state. Reset from the server's own values whenever `detail` changes: once on the first
  // read, and again the moment a save reloads it, so a saved change can never look undone and a
  // failed one is never left half-applied.
  const [displayName, setDisplayName] = useState('');
  const [description, setDescription] = useState('');
  const [scopeKind, setScopeKind] = useState<'self' | 'all'>('self');
  const [parents, setParents] = useState<string[]>([]);
  const [held, setHeld] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!detail) return;
    setDisplayName(detail.displayName);
    setDescription(detail.description);
    setScopeKind(detail.scopeKind);
    setParents(detail.parentRoleIds);
    setHeld(new Set(detail.ownPermissions.map((permission) => `${permission.resource}:${permission.action}`)));
  }, [detail]);

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

  useEffect(() => {
    // Fetched once management is possible, not once "editing" is entered: there is no such mode
    // any more for a manager to have to remember to switch to.
    if (mayManageRoles) { void catalog.reload(); void allRoles.reload(); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mayManageRoles]);

  const dirty = useMemo(() => {
    if (!detail) return false;
    const heldBefore = new Set(detail.ownPermissions.map((permission) => `${permission.resource}:${permission.action}`));
    if (held.size !== heldBefore.size || [...held].some((key) => !heldBefore.has(key))) return true;
    return displayName !== detail.displayName
      || description !== detail.description
      || scopeKind !== detail.scopeKind
      || parents.length !== detail.parentRoleIds.length
      || parents.some((roleId2) => !detail.parentRoleIds.includes(roleId2));
  }, [detail, displayName, description, scopeKind, parents, held]);

  function toggle(key: string) {
    setHeld((was) => {
      const next = new Set(was);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  /**
   * Declares one more action on a resource this realm already has, straight from this screen.
   *
   * `registerCatalog` replaces a server's WHOLE declared catalog per call, not one resource at a
   * time, so every other resource type that server already declares has to be resent unchanged
   * alongside the new action, or it would be read as "no longer declared" and withdrawn. The catalog
   * already fetched for this page carries every entry, so no second read is needed to reconstruct it.
   */
  async function addNewAction(resource: string, action: string) {
    const entries = catalog.data?.permissions ?? [];
    const target = entries.find((entry) => entry.resource === resource);
    if (!target) return;
    const sameServer = entries.filter((entry) => entry.resourceServer === target.resourceServer);

    const grouped = new Map<string, Set<string>>();
    for (const entry of sameServer) {
      const actions = grouped.get(entry.resource) ?? new Set<string>();
      actions.add(entry.action);
      grouped.set(entry.resource, actions);
    }
    const targetActions = grouped.get(resource) ?? new Set<string>();
    targetActions.add(action);
    grouped.set(resource, targetActions);

    const permissions = [...grouped.entries()].flatMap(
      ([res, actions]) => [...actions].map((a) => ({ resource: res, action: a })),
    );

    const done = await catalog.run(
      'add-action',
      () => callApi(`/resource-servers/${encodeURIComponent(target.resourceServer)}/permissions`, {
        method: 'PUT',
        body: { audience: target.resourceServerAudience ?? target.resourceServer, permissions },
        subject: 'that resource server',
      }),
      'That action could not be added to the catalog.',
    );
    // Granting it to THIS role is still the ordinary draft-then-Save this whole screen already
    // uses: added to `held`, which is what makes the page dirty, not saved until Save is pressed.
    if (done) toggle(`${resource}:${action}`);
  }

  async function save() {
    await role.run(
      'save',
      () => callApi(`/roles/${encodeURIComponent(roleId)}`, {
        method: 'PATCH',
        body: {
          displayName,
          description,
          scopeKind,
          parentRoleIds: parents,
          permissions: [...held].map((key) => {
            const [resource, action] = key.split(':');
            return { resource, action };
          }),
        },
        subject: 'that role',
      }),
      'That role could not be changed.',
    );
  }

  async function remove() {
    if (!(await confirm('Remove this role? It is refused while anything still depends on it.'))) return;
    const done = await role.run(
      'delete',
      () => callApi(`/roles/${encodeURIComponent(roleId)}`, { method: 'DELETE', subject: 'that role' }),
      'That role could not be removed.',
    );
    if (done) router.push('/system/roles');
  }

  return (
    <main className="space-y-5">
      <Link href="/system/roles" className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]">
        <ArrowLeft size={13} aria-hidden />
        All roles
      </Link>

      <SectionHeader
        icon={ShieldHalf}
        title={detail ? displayName : 'Role'}
        description={(detail ? description : '') || 'What this role grants, and who holds it.'}
        actions={detail && mayManageRoles
          ? (
            <div className="flex gap-2">
              <ActionButton
                icon={Save}
                label={role.busy === 'save' ? 'Saving…' : 'Save'}
                disabled={!dirty || role.busy === 'save'}
                onClick={() => void save()}
              />
              <Tooltip text={(detail.enabled ?? true)
                ? 'Switches it off. Every assignment survives; it grants nothing, anywhere it is held or inherited from, while it stays this way.'
                : 'Switches it back on. Every assignment already held resumes granting immediately.'}
              >
                <ActionButton
                  icon={Power}
                  label={(detail.enabled ?? true) ? 'Disable' : 'Enable'}
                  tone={(detail.enabled ?? true) ? 'danger' : 'neutral'}
                  busy={role.busy === 'toggle'}
                  onClick={() => void role.run(
                    'toggle',
                    () => callApi(`/roles/${encodeURIComponent(roleId)}`, {
                      method: 'PATCH', body: { enabled: !(detail.enabled ?? true) }, subject: 'that role',
                    }),
                    'That role could not be switched.',
                  )}
                />
              </Tooltip>
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
                  {!(detail.enabled ?? true) && <DisabledBadge />}
                </div>

                {mayManageRoles ? (
                  <>
                    <div className="mt-3 grid gap-3 sm:grid-cols-2">
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
                    <div className="mt-3">
                      <Field label="Description">
                        <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} className={INPUT} />
                      </Field>
                    </div>
                    <div className="mt-3">
                      <Field label="Inherits from" hint="A composition that would loop is refused rather than truncated.">
                        <select
                          multiple
                          value={parents}
                          onChange={(e) => setParents([...e.target.selectedOptions].map((option) => option.value))}
                          className={`${INPUT} h-24`}
                        >
                          {(allRoles.data?.roles ?? [])
                            .filter((candidate) => candidate.roleId !== detail.roleId)
                            .map((candidate) => (
                              <option key={candidate.roleId} value={candidate.roleId}>{candidate.displayName}</option>
                            ))}
                        </select>
                      </Field>
                    </div>
                  </>
                ) : (
                  detail.parents.length > 0 && (
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
                  )
                )}

                <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-4">
                  <Fact label="States" value={`${detail.ownPermissionCount} permissions`} />
                  <Fact label="Grants in total" value={`${detail.effectivePermissionCount} permissions`} />
                  <Fact label="Held by" value={`${detail.assignmentCount} principal${detail.assignmentCount === 1 ? '' : 's'}`} />
                  <Fact label="Last changed" value={when(detail.lastModified)} />
                </dl>

                {detail.sodRationale && (
                  <p className="mt-3 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">
                    {detail.sodRationale}
                  </p>
                )}
              </section>

              <PermissionMatrix
                permissions={detail.effectivePermissions}
                roleName={detail.name}
                editable={mayManageRoles}
                held={held}
                onToggle={toggle}
                catalog={mayManageRoles ? (catalog.data?.permissions ?? []) : []}
                mayAddAction={mayManagePermissions}
                addBusy={catalog.busy === 'add-action'}
                onAddAction={addNewAction}
              />

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

              {mayReadCatalog && mayManageRoles && <CatalogHint />}

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
 *
 * View and edit share every cell. A cell inherited from a parent is never a checkbox here, whether
 * or not `editable`: removing it means editing that role, not this one. A cell this role grants
 * directly becomes an uncheckable-only-here checkbox once `editable`, and a cell the realm's own
 * catalog declares but this role does not yet hold becomes an empty one, so granting something new
 * does not require leaving the page that already shows everything else this role does.
 */
function PermissionMatrix({
  permissions, roleName, editable, held, onToggle, catalog, mayAddAction, addBusy, onAddAction,
}: {
  permissions: ResolvedPermission[];
  roleName: string;
  editable: boolean;
  held: Set<string>;
  onToggle: (key: string) => void;
  catalog: CatalogPermission[];
  mayAddAction: boolean;
  addBusy: boolean;
  onAddAction: (resource: string, action: string) => Promise<void>;
}) {
  const { actions, resources, cells, catalogSet } = useMemo(() => {
    const actionSet = new Set<string>();
    const resourceMap = new Map<string, { server: string }>();
    const cellMap = new Map<string, ResolvedPermission>();
    for (const permission of permissions) {
      actionSet.add(permission.action);
      resourceMap.set(permission.resource, { server: permission.resourceServer });
      cellMap.set(`${permission.resource}:${permission.action}`, permission);
    }
    const catalogKeys = new Set<string>();
    for (const permission of catalog) {
      if (permission.deprecated) continue;
      actionSet.add(permission.action);
      if (!resourceMap.has(permission.resource)) resourceMap.set(permission.resource, { server: permission.resourceServer });
      catalogKeys.add(`${permission.resource}:${permission.action}`);
    }
    return {
      actions: [...actionSet].sort(),
      resources: [...resourceMap.entries()].sort((a, b) => a[0].localeCompare(b[0])),
      cells: cellMap,
      catalogSet: catalogKeys,
    };
  }, [permissions, catalog]);

  if (resources.length === 0) {
    return (
      <EmptyState
        icon={ShieldHalf}
        title={editable ? 'Nothing to grant yet' : 'This role grants nothing'}
        description={editable
          ? 'The realm\'s resource servers have not registered a permission catalog yet, so there is nothing to check here.'
          : 'No permission is written on it and it inherits none. A principal holding it gains no authority.'}
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
                  const key = `${resource}:${action}`;
                  const cell = cells.get(key);
                  const isHeld = held.has(key);
                  // Editable AND (a direct grant, toggleable off, OR not yet granted but the catalog
                  // says it could be). An inherited-only cell never qualifies: that grant belongs to
                  // the parent, and unchecking it here would silently do nothing.
                  const asCheckbox = editable && (isHeld || (!cell && catalogSet.has(key)));

                  return (
                    <td key={action} className="px-3 py-2 text-center">
                      {asCheckbox ? (
                        <Tooltip text={isHeld
                          ? (cell?.unenforced
                            ? `Granted through ${cell.via}, but no resource server declares it, so nothing checks it.`
                            : 'Granted directly by this role. Uncheck to remove it.')
                          : 'Not yet granted. Check to grant it directly.'}
                        >
                          <input
                            type="checkbox"
                            checked={isHeld}
                            onChange={() => onToggle(key)}
                            className="h-4 w-4 rounded border-gray-300 accent-[#00684A]"
                          />
                        </Tooltip>
                      ) : !cell ? (
                        <Minus size={13} className="mx-auto text-gray-200" aria-label="not granted" />
                      ) : (
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

      {mayAddAction && (
        <AddAction resourceNames={resources.map(([resource]) => resource)} busy={addBusy} onAdd={onAddAction} />
      )}
    </section>
  );
}

/**
 * One more action on a resource this realm already declares, registered through the same catalog
 * write `/system/resources` itself uses. Deliberately not a way to declare a brand new resource
 * TYPE: that needs an audience picked first, and already has a full home on that screen; this is
 * the narrower, common case of "one more verb on something that already exists".
 */
function AddAction({ resourceNames, busy, onAdd }: {
  resourceNames: string[];
  busy: boolean;
  onAdd: (resource: string, action: string) => Promise<void>;
}) {
  const [resource, setResource] = useState(resourceNames[0] ?? '');
  const [action, setAction] = useState('');

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (!resource.trim() || !action.trim()) return;
        void onAdd(resource, action.trim()).then(() => setAction(''));
      }}
      className="flex flex-wrap items-end gap-2 border-t border-gray-100 px-4 py-3"
    >
      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Resource</span>
        <select
          value={resource}
          onChange={(e) => setResource(e.target.value)}
          className="mt-1 block h-9 rounded-lg border border-gray-200 px-2.5 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        >
          {resourceNames.map((name) => <option key={name} value={name}>{name}</option>)}
        </select>
      </label>
      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">New action</span>
        <input
          value={action}
          onChange={(e) => setAction(e.target.value)}
          placeholder="archive"
          className="mt-1 block h-9 w-40 rounded-lg border border-gray-200 px-2.5 font-mono text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        />
      </label>
      <button
        type="submit"
        disabled={busy || !resource.trim() || !action.trim()}
        className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-[#001E2B] bg-[#001E2B] px-3 text-xs font-medium text-[#00ED64] disabled:opacity-50"
      >
        <Plus size={12} aria-hidden />
        {busy ? 'Adding…' : 'Add to the catalog'}
      </button>
      <p className="w-full text-[11px] text-gray-400">
        Declares this action on an existing resource, the same registration a resource server's own
        deployment would make, and checks it for this role. Declaring a brand new resource lives at{' '}
        <code>/system/resources</code>.
      </p>
    </form>
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
  const confirm = useConfirm();
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const read = useCallback(
    () => callApi<{ assignments: Assignment[]; total: number }>(`/roles/${encodeURIComponent(roleId)}/assignments`, {
      query: { q: query || undefined, skip: (page - 1) * limit, limit },
      subject: 'who holds this role',
    }),
    [roleId, query, page, limit],
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
    if (!(await confirm('Take this role back? The holder loses it at their next token.'))) return;
    const done = await assignments.run(
      assignment.subjectId,
      // A holding lives on the subject and has no identifier of its own (role.controller.ts's own
      // words for it): addressed by subject and role, never by a standalone assignment id.
      () => callApi(`/principals/${encodeURIComponent(assignment.subjectId)}/roles/${encodeURIComponent(assignment.roleId)}`, {
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

      <ListToolbar
        search={{ value: query, onChange: (next) => { setQuery(next); setPage(1); }, placeholder: 'Search by subject id or user name' }}
      />

      {assignments.error && <ErrorState message={assignments.error} onRetry={() => void assignments.reload()} />}

      {assignments.loading
        ? <LoadingState label="Reading who holds this role…" />
        : rows.length === 0
          ? <EmptyState
              title={query ? 'No holder matches that' : 'Nobody holds this role'}
              description={query ? 'Nothing matches that search.' : 'It grants nothing to anyone until it is assigned.'}
            />
          : (
            <ul className="space-y-3">
              {rows.map((assignment) => (
                <RecordCard
                  key={assignment.subjectId}
                  title={assignment.userName ?? assignment.subjectId}
                  subtitle={assignment.subjectId}
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
                        busy={assignments.busy === assignment.subjectId}
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

      {!assignments.loading && (assignments.data?.total ?? 0) > 0 && (
        <Pagination
          page={page}
          totalPages={Math.max(1, Math.ceil((assignments.data?.total ?? 0) / limit))}
          total={assignments.data?.total ?? 0}
          limit={limit}
          noun="holders"
          onPageChange={setPage}
          onLimitChange={(next) => { setLimit(next); setPage(1); }}
        />
      )}
    </section>
  );
}
