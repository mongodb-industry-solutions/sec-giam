'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, Boxes, Code2, ListChecks, Play, Power, Save, Scale, Trash2,
} from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Pagination } from '../../../../components/Pagination';
import { ListToolbar } from '../../../../components/ListToolbar';
import {
  EmptyState, ErrorState, LoadingState, StatusBadge as CatalogStatusBadge,
} from '../../../../components/ResultState';
import { ActionButton, Fact } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { useConfirm } from '../../../../components/ConfirmProvider';
import { JsonDocumentEditor } from '../../../../components/json/JsonDocumentEditor';
import { Field, INPUT } from '../../roles/parts';
import type { CatalogPermission, RoleSummary } from '../../roles/types';
import { SCIM_PRINCIPAL_EXTENSION, type PrincipalExtension, type ScimList } from '../../../../lib/identities';
import {
  EffectBadge, SelectorPanel, StatusBadge,
  describeCondition, permissionCatalogOptions, resourceLabel, splitPatterns,
  type CatalogOption,
} from '../parts';
import {
  ASSURANCE_LEVELS, CONDITION_KEYS,
  type ConditionKey, type DecisionResult, type PolicyCondition, type PolicyDetail,
  type ResourceCatalogEntry, type ResourceServerCatalogEntry, type Selector,
} from '../types';

/**
 * One policy: what it states, panel by panel, and what it actually decides.
 *
 * Every targeting section (resource, permission, role, principal) is a `Selector`, so every one of
 * them is shown the same way: a searchable, paginated list, each row linking to what it names. View
 * and edit are the SAME body, not two screens: the JSON⇄UI choice is offered in both, because a
 * viewer choosing to read the raw document is not a different need from an editor choosing to write
 * one directly.
 *
 * The simulator is why this screen is worth having beyond the panels. A policy editor with no way to
 * test a rule is exactly how a deny gets written wrong and stays wrong: the rule looks right, nothing
 * appears to break, and the first time anybody finds out is when somebody is refused something they
 * needed or granted something they should not have had.
 */

export default function PolicyDetailPage() {
  const params = useParams<{ policyId: string }>();
  const router = useRouter();
  const confirm = useConfirm();
  const policyId = decodeURIComponent(String(params.policyId));

  const claims = currentClaims();
  const mayManage = can(claims, 'policies', 'manage');

  const read = useCallback(
    () => callApi<PolicyDetail>(`/policies/${encodeURIComponent(policyId)}`, { subject: 'that policy' }),
    [policyId],
  );
  const policy = useConsoleResource(read, 'That policy could not be read.');
  /** Reported by the body below, so this page's own link back can ask before it navigates. */
  const [dirty, setDirty] = useState(false);

  // Fetched here, unconditionally, rather than only while editing: the READ-ONLY panels need these
  // catalogs too, to turn a bare id into a link (a resource's name into its resourceId, a role's
  // name into its roleId) exactly the way `GovernedResources` already resolves a resource's own id.
  const readCatalog = useCallback(
    () => callApi<{ permissions: CatalogPermission[] }>('/permissions', { subject: 'the permission catalog' }),
    [],
  );
  const catalog = useConsoleResource(readCatalog, 'The permission catalog could not be read.');
  const readResources = useCallback(
    () => callApi<{ resourceServers: ResourceServerCatalogEntry[] }>(
      '/resource-servers', { query: { limit: 200 }, subject: 'the resource server catalog' },
    ),
    [],
  );
  const resourceServers = useConsoleResource(readResources, 'The resource server catalog could not be read.');
  const readRoles = useCallback(
    () => callApi<{ roles: RoleSummary[] }>('/roles', { query: { limit: 200 }, subject: 'the roles in this realm' }),
    [],
  );
  const allRoles = useConsoleResource(readRoles, 'The roles could not be read.');
  /**
   * The directory, so Principal is a list like the other three rather than a text box.
   *
   * Capped, and deliberately: a realm's identity directory has no fixed size the way a resource or
   * role catalog does. What is read is enough to pick from and to recognise an id already named;
   * anything beyond it is still nameable through the panel's own field.
   */
  const readPrincipals = useCallback(
    () => callApi<ScimList>('/scim/v2/Users', { query: { count: 200 }, subject: 'the principal directory' }),
    [],
  );
  const principals = useConsoleResource(readPrincipals, 'The principal directory could not be read.');
  useEffect(() => {
    void catalog.reload(); void resourceServers.reload(); void allRoles.reload(); void principals.reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * The catalog entry behind each resource NAME, not just its id.
   *
   * A policy stores a resource by name (`roles`), and a name on its own reads as a stray word: the
   * screens below have to be able to say which resource server declares it, what it is called for a
   * reader, and what may be done to it. All of that is already in the catalog this page fetches, so
   * resolving it here costs nothing and keeps both panels from inventing their own idea of it.
   */
  const resourceByName = new Map(
    (resourceServers.data?.resourceServers ?? []).flatMap((server) => server.resources.map((entry) => [
      entry.name,
      {
        resourceId: entry.resourceId,
        displayName: entry.displayName,
        description: entry.description,
        actions: entry.actions ?? [],
        serverName: server.displayName ?? server.name,
      },
    ] as const)),
  );

  // What the pickers offer: the id a policy stores, the name a person recognises, and the resource
  // server that declares it. A bare id is what made choosing one an exercise in recalling spellings.
  const resourceCatalogOptions: CatalogOption[] = [...resourceByName]
    .map(([name, entry]) => ({ id: name, label: entry.displayName, group: entry.serverName }))
    .sort((left, right) => left.id.localeCompare(right.id));
  const roleCatalogOptions: CatalogOption[] = (allRoles.data?.roles ?? [])
    .map((role) => ({ id: role.name, label: role.displayName, group: role.scopeKind }))
    .sort((left, right) => left.id.localeCompare(right.id));
  // A policy names a principal by SUBJECT id, so that is the row's id; the login is what a person
  // recognises, and the kind is what distinguishes a service from somebody who signs in.
  const principalCatalogOptions: CatalogOption[] = (principals.data?.Resources ?? [])
    .map((entry) => ({
      id: entry.id,
      label: entry.name?.formatted ?? entry.userName,
      group: (entry[SCIM_PRINCIPAL_EXTENSION] as PrincipalExtension | undefined)?.kind,
      detail: entry.userName,
    }))
    .sort((left, right) => (left.label ?? '').localeCompare(right.label ?? ''));

  async function save(patch: Record<string, unknown>) {
    const done = await policy.run(
      'save',
      () => callApi(`/policies/${encodeURIComponent(policyId)}`, { method: 'PATCH', body: patch, subject: 'that policy' }),
      'That policy could not be changed.',
    );
    if (done) setDirty(false);
  }

  async function remove() {
    if (!(await confirm('Remove this policy? Removing one that denies widens access immediately, and this cannot be undone. Retiring it is reversible.'))) return;
    const done = await policy.run(
      'delete',
      () => callApi(`/policies/${encodeURIComponent(policyId)}`, { method: 'DELETE', subject: 'that policy' }),
      'That policy could not be removed.',
    );
    if (done) router.push('/system/policies');
  }

  const detail = policy.data;

  return (
    <main className="space-y-5">
      <Link
        href="/system/policies"
        onClick={async (event) => {
          if (!dirty) return;
          event.preventDefault();
          if (await confirm({
            title: 'Unsaved changes',
            message: 'This policy has changes that have not been saved. Discard them and leave, or stay and save them from the bar at the bottom of the screen.',
            confirmLabel: 'Discard and leave',
            cancelLabel: 'Stay here',
          })) router.push('/system/policies');
        }}
        className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]"
      >
        <ArrowLeft size={13} aria-hidden />
        All policies
      </Link>

      <SectionHeader
        icon={Scale}
        title={detail?.name ?? 'Policy'}
        description="What this policy states, and what the authority decides once every evaluator has spoken."
        actions={detail && mayManage
          ? (
            <div className="flex gap-2">
              <Tooltip text={detail.status === 'active'
                ? 'Retires it. Kept for the record rather than deleted, and it decides nothing while retired.'
                : 'Switches it on. It decides from its next evaluation onward.'}
              >
                <ActionButton
                  icon={Power}
                  label={detail.status === 'active' ? 'Retire' : 'Activate'}
                  busy={policy.busy === 'toggle'}
                  onClick={() => void policy.run(
                    'toggle',
                    () => callApi(`/policies/${encodeURIComponent(policyId)}`, {
                      method: 'PATCH', body: { status: detail.status === 'active' ? 'retired' : 'active' }, subject: 'that policy',
                    }),
                    'That policy could not be switched.',
                  )}
                />
              </Tooltip>
              <ActionButton icon={Trash2} label="Remove" tone="danger" busy={policy.busy === 'delete'} onClick={() => void remove()} />
            </div>
          )
          : undefined}
      />

      {policy.error && <ErrorState message={policy.error} onRetry={() => void policy.reload()} />}

      {policy.loading && !detail
        ? <LoadingState label="Reading the policy…" />
        : !detail
          ? null
          : (
            <>
              <section className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-gray-400">version {detail.version}</span>
                  <EffectBadge effect={detail.effect} />
                  <StatusBadge status={detail.status} />
                </div>
                <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-4">
                  <Fact label="Permissions" value={`${detail.permissionCount}`} />
                  <Fact label="Conditional" value={`${detail.conditionCount}`} />
                  <Fact label="In effect" value={detail.inEffect ? 'yes' : 'no'} />
                  <Fact label="Last changed" value={when(detail.lastModified)} />
                </dl>
                {!detail.inEffect && (
                  <p className="mt-3 border-l-2 border-amber-200 pl-2.5 text-sm text-gray-600">
                    Not in effect right now, so this rule decides nothing. The simulator below reflects
                    that: it asks the authority rather than reading this document.
                  </p>
                )}
                {detail.reason && (
                  <p className="mt-3 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">{detail.reason}</p>
                )}
              </section>

              <PolicyBody
                // Keyed on the version so a save, which reloads the policy, restarts the drafts from
                // what the server now holds. Without it the fields would keep the values that were
                // just saved and `dirty` would go on comparing against a stale original.
                key={`${detail.policyId}:${detail.version}:${detail.lastModified ?? ''}`}
                detail={detail}
                busy={policy.busy === 'save'}
                canEdit={mayManage}
                onSave={save}
                onDirtyChange={setDirty}
                permissionCatalog={catalog.data?.permissions ?? []}
                resourceCatalog={resourceCatalogOptions}
                roleCatalog={roleCatalogOptions}
                principalCatalog={principalCatalogOptions}
                allRoles={allRoles.data?.roles ?? []}
              />

              {/* What the SAVED policy currently reaches, resolved by the authority rather than read
                * off the draft above: it answers "and what does that actually mean today". */}
              <GovernedResources
                policyId={detail.policyId}
                resourceSelector={detail.resource}
                resourceByName={resourceByName}
              />

              <Simulator policyId={detail.policyId} subjectId={claims?.sub ?? ''} />
            </>
          )}
    </main>
  );
}

/** The Form/JSON tabs, identical wherever they appear: viewing a policy or editing one. */
function ModeTabs({ mode, onChange }: { mode: 'ui' | 'json'; onChange: (mode: 'ui' | 'json') => void }) {
  return (
    <div className="flex gap-1 text-xs">
      <button
        type="button"
        onClick={() => onChange('ui')}
        className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium ${mode === 'ui' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-500 hover:text-gray-700'}`}
      >
        <ListChecks size={12} aria-hidden />
        UI
      </button>
      <button
        type="button"
        onClick={() => onChange('json')}
        className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium ${mode === 'json' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-500 hover:text-gray-700'}`}
      >
        <Code2 size={12} aria-hidden />
        JSON
      </button>
    </div>
  );
}

/**
 * A plain, paginated list of ids, each linking to what it names when a link is known. Shared by
 * Principals, Permissions and Roles, so the three panels the plan asks to look identical actually
 * share ONE implementation rather than three copies of the same search-and-page scaffold.
 */
/**
 * What a policy states, editable in place. There is no separate view.
 *
 * Every field starts equal to the loaded policy and stays that way until something is actually
 * changed, so `dirty` is what enables Save and there is no mode to enter first. Leaving with
 * something unsaved asks, in the browser and on this page's own link back.
 */
/**
 * The statement a policy makes, in exactly the shape `PATCH .../policies/:policyId` accepts.
 *
 * One function, used for the loaded policy, for the draft and for the JSON document, so the three
 * cannot disagree about what "everything this policy says" means. The JSON tab shows this and
 * nothing less: effect, all four selectors, the conditions and the reason.
 */
interface PolicyStatement {
  effect: 'allow' | 'deny';
  resource: Selector;
  permission: Selector;
  role: Selector;
  principal: Selector;
  conditions: PolicyCondition[];
  reason: string;
}

function statedBy(detail: PolicyDetail): PolicyStatement {
  return {
    effect: detail.effect,
    resource: detail.resource ?? {},
    permission: detail.permission ?? {},
    role: detail.role ?? {},
    principal: detail.principal ?? {},
    conditions: detail.conditions ?? [],
    reason: detail.reason ?? '',
  };
}

/** The document, or null while it is mid-edit and not yet valid JSON. */
function parsedOrNull(json: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(json) as unknown;
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/**
 * Two statements are the same when they say the same thing, key order aside.
 *
 * Compared as canonical JSON rather than field by field: a selector is `{ids}` or `{pattern}`, a
 * condition is a small object of optional keys, and enumerating those by hand here is how a
 * comparison drifts out of step with the document it is supposed to be comparing.
 */
function sameStatement(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  return canonical(left) === canonical(right);
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      // An absent selector and an empty one state the same thing, and the API accepts either.
      .filter(([, held]) => held !== undefined && !(Array.isArray(held) && held.length === 0))
      .sort(([a], [b]) => a.localeCompare(b));
    return `{${entries.map(([key, held]) => `${key}:${canonical(held)}`).join(',')}}`;
  }
  // '' and absent are the same answer for `reason`, which is how the API treats it.
  if (value === '' || value === null) return '';
  return JSON.stringify(value) ?? '';
}

function PolicyBody({
  detail, busy, canEdit, onSave, onDirtyChange,
  permissionCatalog, resourceCatalog, roleCatalog, principalCatalog, allRoles,
}: {
  detail: PolicyDetail;
  busy: boolean;
  /** False for a reader without `policies:manage`: the same screen, with nothing to change. */
  canEdit: boolean;
  onSave: (patch: Record<string, unknown>) => void;
  /** Lifted so the page's own link back can ask before it navigates. */
  onDirtyChange: (dirty: boolean) => void;
  permissionCatalog: CatalogPermission[];
  resourceCatalog: CatalogOption[];
  roleCatalog: CatalogOption[];
  principalCatalog: CatalogOption[];
  allRoles: RoleSummary[];
}) {
  const [effect, setEffect] = useState(detail.effect);

  const [resourceMode, setResourceMode] = useState<'ids' | 'pattern'>(detail.resource.pattern && !detail.resource.ids?.length ? 'pattern' : 'ids');
  const [resourceIds, setResourceIds] = useState((detail.resource.ids ?? []).join(', '));
  const [resourcePattern, setResourcePattern] = useState(detail.resource.pattern ?? '');

  const [permissionMode, setPermissionMode] = useState<'ids' | 'pattern'>(detail.permission.pattern && !detail.permission.ids?.length ? 'pattern' : 'ids');
  const [permissionIds, setPermissionIds] = useState((detail.permission.ids ?? []).join(', '));
  const [permissionPattern, setPermissionPattern] = useState(detail.permission.pattern ?? '');

  const [roleMode, setRoleMode] = useState<'ids' | 'pattern'>(detail.role?.pattern && !detail.role?.ids?.length ? 'pattern' : 'ids');
  const [roleIds, setRoleIds] = useState((detail.role?.ids ?? []).join(', '));
  const [rolePattern, setRolePattern] = useState(detail.role?.pattern ?? '');

  const [principalMode, setPrincipalMode] = useState<'ids' | 'pattern'>(detail.principal?.pattern && !detail.principal?.ids?.length ? 'pattern' : 'ids');
  const [principalIds, setPrincipalIds] = useState((detail.principal?.ids ?? []).join(', '));
  const [principalPattern, setPrincipalPattern] = useState(detail.principal?.pattern ?? '');

  const [reason, setReason] = useState(detail.reason ?? '');
  const [condition, setCondition] = useState<PolicyCondition | undefined>(detail.conditions[0]);

  function changeCondition(patch: PolicyCondition | undefined) {
    setCondition(patch === undefined || Object.keys(patch).length === 0 ? undefined : patch);
  }

  function buildPatch(): Record<string, unknown> {
    const sent = condition
      ? Object.fromEntries(Object.entries(condition).filter(([, value]) => !(Array.isArray(value) && value.length === 0)))
      : undefined;
    const permission: Selector = permissionMode === 'ids' ? { ids: splitPatterns(permissionIds) } : { pattern: permissionPattern };
    const role: Selector = roleMode === 'ids' ? { ids: splitPatterns(roleIds) } : { pattern: rolePattern };
    const principal: Selector = principalMode === 'ids' ? { ids: splitPatterns(principalIds) } : { pattern: principalPattern };
    return {
      effect,
      resource: resourceMode === 'ids' ? { ids: splitPatterns(resourceIds) } : { pattern: resourcePattern },
      permission,
      role,
      principal,
      conditions: sent && Object.keys(sent).length > 0 ? [sent] : [],
      ...(reason.trim() ? { reason: reason.trim() } : { reason: '' }),
    };
  }

  const [mode, setMode] = useState<'ui' | 'json'>('ui');
  /** Inside the JSON tab: the tree, which is where a value is edited, or the raw document. */
  const [jsonShape, setJsonShape] = useState<'tree' | 'raw'>('tree');
  const [json, setJson] = useState(() => JSON.stringify(statedBy(detail), null, 2));
  const [jsonError, setJsonError] = useState<string | null>(null);
  const previousMode = useRef<'ui' | 'json'>('ui');

  /**
   * What is unsaved, answered by comparing the whole statement to the one that was loaded.
   *
   * Field by field rather than by a flag somebody has to remember to set: a flag set in one of the
   * dozen `onChange` handlers here and forgotten in another is a Save button that stays grey over
   * real changes, which is worse than no button at all. Whichever tab the change was made in, the
   * comparison is the same, so editing the JSON enables Save exactly as ticking a row does.
   */
  const stated = mode === 'json' ? parsedOrNull(json) : buildPatch();
  const dirty = stated !== null && !sameStatement(stated, statedBy(detail) as unknown as Record<string, unknown>);

  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);

  // A refresh, a closed tab, a typed URL: `beforeunload` is the only hook for any of the three, and
  // the text is no longer shown by any supported browser, only the fact that one fires.
  useEffect(() => {
    if (!dirty) return;
    function warn(event: BeforeUnloadEvent) {
      event.preventDefault();
      event.returnValue = '';
    }
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  /** Back to exactly what the server holds, in both tabs at once. */
  function discard() {
    const loaded = statedBy(detail);
    setEffect(detail.effect);
    applySelector('resource', loaded.resource);
    applySelector('permission', loaded.permission);
    applySelector('role', loaded.role);
    applySelector('principal', loaded.principal);
    setReason(detail.reason ?? '');
    setCondition(detail.conditions[0]);
    setJson(JSON.stringify(loaded, null, 2));
    setJsonError(null);
  }

  /** One selector's two fields and its mode, set from a stored selector. Used by discard and by JSON. */
  function applySelector(which: 'resource' | 'permission' | 'role' | 'principal', selector: Selector | undefined) {
    const byPattern = Boolean(selector?.pattern && !selector.ids?.length);
    const setters = {
      resource: [setResourceMode, setResourceIds, setResourcePattern] as const,
      permission: [setPermissionMode, setPermissionIds, setPermissionPattern] as const,
      role: [setRoleMode, setRoleIds, setRolePattern] as const,
      principal: [setPrincipalMode, setPrincipalIds, setPrincipalPattern] as const,
    }[which];
    setters[0](byPattern ? 'pattern' : 'ids');
    setters[1]((selector?.ids ?? []).join(', '));
    setters[2](selector?.pattern ?? '');
  }

  function changeMode(next: 'ui' | 'json') {
    if (next === previousMode.current) return;
    if (next === 'json') {
      setJson(JSON.stringify(buildPatch(), null, 2));
      setJsonError(null);
    } else {
      try {
        const parsed = JSON.parse(json) as {
          effect?: 'allow' | 'deny'; resource?: Selector; permission?: Selector; role?: Selector;
          principal?: Selector; reason?: string; conditions?: PolicyCondition[];
        };
        if (parsed.effect === 'allow' || parsed.effect === 'deny') setEffect(parsed.effect);
        const resource = parsed.resource ?? {};
        if (resource.pattern && !resource.ids?.length) { setResourceMode('pattern'); setResourcePattern(resource.pattern); } else {
          setResourceMode('ids'); setResourceIds((resource.ids ?? []).join(', '));
        }
        const permission = parsed.permission ?? {};
        if (permission.pattern && !permission.ids?.length) { setPermissionMode('pattern'); setPermissionPattern(permission.pattern); } else {
          setPermissionMode('ids'); setPermissionIds((permission.ids ?? []).join(', '));
        }
        const role = parsed.role ?? {};
        if (role.pattern && !role.ids?.length) { setRoleMode('pattern'); setRolePattern(role.pattern); } else {
          setRoleMode('ids'); setRoleIds((role.ids ?? []).join(', '));
        }
        const principal = parsed.principal ?? {};
        if (principal.pattern && !principal.ids?.length) { setPrincipalMode('pattern'); setPrincipalPattern(principal.pattern); } else {
          setPrincipalMode('ids'); setPrincipalIds((principal.ids ?? []).join(', '));
        }
        setReason(parsed.reason ?? '');
        setCondition(parsed.conditions?.[0]);
        setJsonError(null);
      } catch {
        setJsonError('This is not valid JSON. Fix it, or switch back to JSON to keep editing it.');
        previousMode.current = next;
        setMode(next);
        return;
      }
    }
    previousMode.current = next;
    setMode(next);
  }

  let jsonParseError: string | null = null;
  if (mode === 'json') {
    try { JSON.parse(json); } catch { jsonParseError = 'This is not valid JSON.'; }
  }

  const resourceGiven = resourceMode === 'ids' ? resourceIds.trim() : resourcePattern.trim();
  const governsSomething = permissionMode === 'ids' ? Boolean(permissionIds.trim()) : Boolean(permissionPattern.trim());
  const rolesSomething = roleMode === 'ids' ? Boolean(roleIds.trim()) : Boolean(rolePattern.trim());

  /**
   * Why Save is refused, in words, or null when it is not.
   *
   * A disabled button with no reason beside it is the same as a broken one: the two rules the API
   * enforces are that a policy names a resource and that it covers something, and both are things a
   * person can only satisfy if they are told.
   */
  const invalid = mode === 'json'
    ? (jsonParseError ? 'this is not valid JSON' : null)
    : !resourceGiven
      ? 'name a resource first'
      : !(governsSomething || rolesSomething)
        ? 'name a permission or a role'
        : null;

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (mode === 'json') {
          try {
            onSave(JSON.parse(json) as Record<string, unknown>);
          } catch {
            setJsonError('This is not valid JSON.');
          }
          return;
        }
        onSave(buildPatch());
      }}
      className="space-y-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-semibold text-[#001E2B]">What it states</h2>
        <ModeTabs mode={mode} onChange={changeMode} />
      </div>

      {mode === 'json' ? (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-gray-500">
              The whole statement, in the shape `PATCH /realms/:realm/policies/:policyId` accepts:
              effect, all four selectors, the conditions and the reason. Editing it here is the same
              edit as ticking a row, and enables Save the same way.
            </p>
            {/* The tree edits a value in place; the raw document is where a key or an array entry
              * is added, which a tree cannot offer. Both write the same document. */}
            <div className="inline-flex shrink-0 rounded-lg border border-gray-200 p-0.5 text-[11px]">
              {(['tree', 'raw'] as const).map((shape) => (
                <button
                  key={shape}
                  type="button"
                  onClick={() => setJsonShape(shape)}
                  aria-pressed={jsonShape === shape}
                  className={`rounded-md px-2 py-0.5 transition-colors ${
                    jsonShape === shape ? 'bg-[#001E2B] text-white' : 'text-gray-500 hover:text-[#001E2B]'
                  }`}
                >
                  {shape === 'tree' ? 'Tree' : 'Raw'}
                </button>
              ))}
            </div>
          </div>

          {jsonShape === 'tree' && parsedOrNull(json) ? (
            <JsonDocumentEditor
              value={parsedOrNull(json) as object}
              editable={canEdit}
              onChange={(next) => { setJson(next); setJsonError(null); }}
            />
          ) : (
            <textarea
              value={json}
              onChange={(e) => { setJson(e.target.value); setJsonError(null); }}
              rows={18}
              spellCheck={false}
              readOnly={!canEdit}
              className="w-full rounded-lg border border-gray-200 bg-gray-50 p-3 font-mono text-xs text-gray-800 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          )}
          {jsonShape === 'tree' && !parsedOrNull(json) && (
            <p className="text-xs text-amber-700">
              Not valid JSON, so there is no tree to show. Fix it in Raw.
            </p>
          )}
          {(jsonError ?? jsonParseError) && <p className="text-xs text-red-600">{jsonError ?? jsonParseError}</p>}
        </div>
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Effect" hint="Deny wins over every allow in the realm.">
              <select value={effect} onChange={(e) => setEffect(e.target.value as 'allow' | 'deny')} className={INPUT}>
                <option value="allow">Allow</option>
                <option value="deny">Deny</option>
              </select>
            </Field>
          </div>

          <SelectorPanel
            noun="Resource"
            description="What this policy governs. Tick each resource it attaches to."
            mode={resourceMode} onModeChange={setResourceMode}
            ids={resourceIds} onIdsChange={setResourceIds}
            pattern={resourcePattern} onPatternChange={setResourcePattern}
            catalog={resourceCatalog}
            columns={{ group: 'Resource server' }}
            disabled={!canEdit}
          />

          <SelectorPanel
            noun="Permission"
            description="What it covers, resource and action. A role below adds whatever it currently grants."
            mode={permissionMode} onModeChange={setPermissionMode}
            ids={permissionIds} onIdsChange={setPermissionIds}
            pattern={permissionPattern} onPatternChange={setPermissionPattern}
            catalog={permissionCatalogOptions(permissionCatalog)}
            columns={{ group: 'Resource server' }}
            required={false}
            disabled={!canEdit}
          />

          <SelectorPanel
            noun="Role"
            description="Every permission these roles currently grant, parents included, is folded into what this policy covers. At least one of Permission or Role must resolve to something."
            mode={roleMode} onModeChange={setRoleMode}
            ids={roleIds} onIdsChange={setRoleIds}
            pattern={rolePattern} onPatternChange={setRolePattern}
            catalog={roleCatalog}
            columns={{ group: 'Scope' }}
            required={false}
            emptyCatalog="No role is registered in this realm yet."
            disabled={!canEdit}
          />

          <SelectorPanel
            noun="Principal"
            description="Who it applies to. Ticking nobody applies it to everybody, which is what an empty list means here."
            mode={principalMode} onModeChange={setPrincipalMode}
            ids={principalIds} onIdsChange={setPrincipalIds}
            pattern={principalPattern} onPatternChange={setPrincipalPattern}
            catalog={principalCatalog}
            columns={{ group: 'Kind', detail: 'Subject' }}
            required={false}
            emptyCatalog="No principal was read back from the directory."
            disabled={!canEdit}
          />

          <ConditionEditor
            condition={condition}
            onChange={changeCondition}
            roles={allRoles}
            permissions={permissionCatalog}
          />

          <Field label="Reason" hint="Carried into the decision. Write what a reader should understand months from now.">
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} className={INPUT} />
          </Field>
        </>
      )}

      {/*
        * The save bar, and it only exists while there is something to save.
        *
        * Sticky rather than at the bottom of a long form: the four panels below are lists that
        * scroll, so a button under them is a button somebody has to go looking for to find out
        * whether their change took. It states what is unsaved, saves it, or puts everything back.
        */}
      {dirty && (
        <div className="sticky bottom-3 z-10 flex flex-wrap items-center gap-2 rounded-xl border border-[#00ED64]/40 bg-white/95 p-2.5 shadow-lg backdrop-blur">
          <span className="mr-auto text-xs text-gray-600">
            Unsaved changes
            {invalid && <span className="ml-1.5 text-amber-700">{invalid}</span>}
          </span>
          <button
            type="button"
            onClick={discard}
            disabled={busy}
            className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:border-[#001E2B] hover:text-[#001E2B] disabled:opacity-50"
          >
            Discard
          </button>
          <button
            type="submit"
            disabled={busy || Boolean(invalid)}
            className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
          >
            <Save size={12} aria-hidden />
            {busy ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      )}
    </form>
  );
}

/**
 * The closed condition set, and nothing else.
 *
 * Each of the five is a checkbox with its own control. There is no free-text row and no "other",
 * which is the whole point: what a policy may say about a request is what this authority can
 * actually observe about the identity making it.
 */
function ConditionEditor({ condition, onChange, roles, permissions }: {
  condition?: PolicyCondition;
  onChange: (next: PolicyCondition | undefined) => void;
  roles: RoleSummary[];
  permissions: CatalogPermission[];
}) {
  const held = condition ?? {};

  function set(key: ConditionKey, value: unknown) {
    const next = { ...held } as Record<string, unknown>;
    if (value === undefined) delete next[key];
    else next[key] = value;
    onChange(next as PolicyCondition);
  }

  function toggle(key: ConditionKey, on: boolean) {
    const defaults: Record<ConditionKey, unknown> = {
      assuranceAtLeast: 'aal2',
      ipInRange: ['10.'],
      timeOfDayUtc: { from: 8, to: 18 },
      tenantIs: 'default',
      attestationRequired: true,
      heldRole: [],
      heldPermission: [],
    };
    set(key, on ? defaults[key] : undefined);
  }

  function toggleMember(key: 'heldRole' | 'heldPermission', value: string, checked: boolean) {
    const current = (held[key] as string[] | undefined) ?? [];
    set(key, checked ? [...current, value] : current.filter((entry) => entry !== value));
  }

  const labels: Record<ConditionKey, string> = {
    assuranceAtLeast: 'Assurance at least',
    ipInRange: 'Address starts with',
    timeOfDayUtc: 'Hour of day (UTC)',
    tenantIs: 'Tenant is',
    attestationRequired: 'Attestation required',
    heldRole: 'Role already held',
    heldPermission: 'Permission already held',
  };

  return (
    <fieldset className="mt-3">
      <legend className="text-xs font-medium text-gray-600">Condition</legend>
      <Tooltip text="Identity context only, and this list is all of it. A condition naming a business threshold would be a judgement about inputs this authority cannot observe, so there is no way to write one.">
        <p className="mt-0.5 text-[11px] text-gray-400">
          Assurance, network, time, tenant, attestation, and what the subject already holds. There is
          nothing else a policy may say.
        </p>
      </Tooltip>

      <div className="mt-2 space-y-2 rounded-lg border border-gray-100 bg-white p-3">
        {CONDITION_KEYS.map((key) => {
          const on = held[key] !== undefined;
          return (
            <div key={key} className="flex flex-wrap items-center gap-3">
              <label className="inline-flex w-48 shrink-0 items-center gap-1.5 text-xs text-gray-600">
                <input type="checkbox" checked={on} onChange={(e) => toggle(key, e.target.checked)} className="rounded border-gray-300" />
                {labels[key]}
              </label>

              {on && key === 'assuranceAtLeast' && (
                <select
                  value={held.assuranceAtLeast}
                  onChange={(e) => set(key, e.target.value)}
                  className="rounded-lg border border-gray-200 px-2 py-1 text-xs text-gray-700"
                >
                  {ASSURANCE_LEVELS.map((level) => <option key={level} value={level}>{level}</option>)}
                </select>
              )}

              {on && key === 'ipInRange' && (
                <input
                  value={(held.ipInRange ?? []).join(', ')}
                  onChange={(e) => set(key, splitPatterns(e.target.value))}
                  placeholder="10., 192.168."
                  className="min-w-48 flex-1 rounded-lg border border-gray-200 px-2 py-1 text-xs text-gray-700"
                />
              )}

              {on && key === 'timeOfDayUtc' && (
                <span className="inline-flex items-center gap-1.5 text-xs text-gray-600">
                  from
                  <input
                    type="number" min={0} max={23}
                    value={held.timeOfDayUtc?.from ?? 0}
                    onChange={(e) => set(key, { from: Number(e.target.value), to: held.timeOfDayUtc?.to ?? 0 })}
                    className="w-16 rounded-lg border border-gray-200 px-2 py-1 text-xs"
                  />
                  to
                  <input
                    type="number" min={0} max={23}
                    value={held.timeOfDayUtc?.to ?? 0}
                    onChange={(e) => set(key, { from: held.timeOfDayUtc?.from ?? 0, to: Number(e.target.value) })}
                    className="w-16 rounded-lg border border-gray-200 px-2 py-1 text-xs"
                  />
                  <span className="text-gray-400">half open, and a smaller end wraps midnight</span>
                </span>
              )}

              {on && key === 'tenantIs' && (
                <input
                  value={held.tenantIs ?? ''}
                  onChange={(e) => set(key, e.target.value)}
                  className="min-w-48 flex-1 rounded-lg border border-gray-200 px-2 py-1 text-xs text-gray-700"
                />
              )}

              {on && key === 'attestationRequired' && (
                <span className="text-xs text-gray-400">the caller must arrive already attested</span>
              )}

              {on && key === 'heldRole' && (
                <div className="min-w-48 flex-1">
                  <p className="text-[11px] text-gray-400">Any one of the checked roles satisfies it.</p>
                  <div className="mt-1 max-h-40 overflow-y-auto rounded-lg border border-gray-200 p-2">
                    {roles.length === 0
                      ? <p className="text-xs text-gray-400">No role is registered in this realm yet.</p>
                      : roles.map((role) => (
                        <label key={role.roleId} className="flex items-center gap-1.5 py-0.5 text-xs text-gray-700">
                          <input
                            type="checkbox"
                            checked={(held.heldRole ?? []).includes(role.name)}
                            onChange={(e) => toggleMember('heldRole', role.name, e.target.checked)}
                            className="rounded border-gray-300"
                          />
                          {role.displayName} <span className="font-mono text-gray-400">({role.name})</span>
                        </label>
                      ))}
                  </div>
                </div>
              )}

              {on && key === 'heldPermission' && (
                <div className="min-w-48 flex-1">
                  <p className="text-[11px] text-gray-400">Every checked permission must already be held, all of them at once.</p>
                  <div className="mt-1 max-h-40 overflow-y-auto rounded-lg border border-gray-200 p-2">
                    {permissions.length === 0
                      ? <p className="text-xs text-gray-400">The permission catalog is empty.</p>
                      : permissions.map((permission) => {
                        const value = `${permission.resource}:${permission.action}`;
                        return (
                          <label key={value} className="flex items-center gap-1.5 py-0.5 text-xs text-gray-700">
                            <input
                              type="checkbox"
                              checked={(held.heldPermission ?? []).includes(value)}
                              onChange={(e) => toggleMember('heldPermission', value, e.target.checked)}
                              className="rounded border-gray-300"
                            />
                            <span className="font-mono">{value}</span>
                          </label>
                        );
                      })}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

/**
 * Which of this realm's own resources this policy actually governs, as an ordinary list: a name
 * on its own is not "visible" the way a link, a status and a search box are.
 *
 * `resource.ids` and `resource.pattern` are exclusive in effect (ids wins when both are stored), so
 * there is nothing here to reconcile: whichever one actually decides is the only one this reads, and
 * the read comes from the SAME `selectorApplies` the decision engine itself uses, never a second,
 * approximate idea of what either one means. Fetched once (a realm's catalog is small enough to read
 * whole, the same call `/permissions` and `/resource-servers` already make), search and paging
 * happen over what was already read.
 */
function GovernedResources({ policyId, resourceSelector, resourceByName }: {
  policyId: string;
  resourceSelector: Selector;
  resourceByName: Map<string, ResourceCatalogEntry>;
}) {
  const read = useCallback(
    () => callApi<{ resources: Array<{ resourceId: string; name: string; status: string }>; total: number }>(
      `/policies/${encodeURIComponent(policyId)}/resources`,
      { subject: 'the resources this policy governs' },
    ),
    [policyId],
  );
  const resources = useConsoleResource(read, 'The resources this policy governs could not be read.');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const all = resources.data?.resources ?? [];
  const filtered = query ? all.filter((r) => r.name.toLowerCase().includes(query.toLowerCase())) : all;
  const total = filtered.length;
  const rows = filtered.slice((page - 1) * limit, page * limit);

  return (
    <section className="space-y-3">
      <div>
        <h2 className="font-semibold text-[#001E2B]">Resources this policy governs</h2>
        <p className="mt-0.5 text-sm text-gray-500">
          {resourceSelector.pattern && !resourceSelector.ids?.length
            ? `Every resource in this realm's catalog the pattern (${resourceSelector.pattern}) currently matches. A pattern names no resource directly, so this is the only place to see which ones it actually reaches.`
            : 'Named exactly: this policy attaches to each of these directly, and to nothing a pattern alone might otherwise have matched. Each one opens its own page, where the other policies governing it are listed.'}
        </p>
      </div>

      <ListToolbar search={{ value: query, onChange: (next) => { setQuery(next); setPage(1); }, placeholder: 'Search by name' }} />

      {resources.error && <ErrorState message={resources.error} onRetry={() => void resources.reload()} />}
      {resources.loading && <LoadingState label="Reading the resources this policy governs…" />}

      {!resources.loading && !resources.error && total === 0 && (
        <EmptyState
          icon={Boxes}
          title={query ? 'No resource matches that' : 'This policy governs no resource yet'}
          description={query
            ? 'Nothing in the current match set matches that search.'
            : resourceSelector.pattern
              ? 'Nothing in this realm\'s resource catalog matches this pattern right now.'
              : 'The ids on this policy do not (or no longer) correspond to a registered resource.'}
        />
      )}

      {/*
        * A table, because these rows are the same few fields repeated and nothing else.
        *
        * Stacked cards put a name, a label, a sentence and a list of verbs in a column per row, so
        * comparing two resources meant reading two paragraphs. Columns line the same field up
        * across rows, which is the whole reason a table exists.
        *
        * Narrow screens drop columns rather than squeezing them: the name is the identifier and
        * the link, so it survives every width; the resource server appears from `sm`, the
        * description from `lg`, the declared actions from `xl`. What a dropped column held is
        * still reachable by opening the resource, which is what the name links to.
        */}
      {!resources.loading && rows.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-gray-200">
          <table className="w-full table-fixed text-left text-sm">
            <thead className="bg-gray-50 text-[10px] uppercase tracking-wider text-gray-400">
              <tr>
                <th scope="col" className="w-1/2 px-3 py-2 font-medium sm:w-1/3 lg:w-1/5">Name</th>
                <th scope="col" className="hidden px-3 py-2 font-medium sm:table-cell sm:w-1/3 lg:w-1/5">Resource server</th>
                <th scope="col" className="hidden px-3 py-2 font-medium lg:table-cell lg:w-2/5">Description</th>
                <th scope="col" className="hidden px-3 py-2 font-medium xl:table-cell xl:w-1/6">Actions</th>
                <th scope="col" className="w-1/2 px-3 py-2 font-medium sm:w-1/6 lg:w-[10%]">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {rows.map((resource) => {
                const entry = resourceByName.get(resource.name);
                return (
                  <tr key={resource.resourceId} className="align-top hover:bg-gray-50">
                    <td className="px-3 py-2">
                      {/*
                        * The name is the key AND the link: it is what this policy stores, what a
                        * permission is built from, and what somebody reads the row by.
                        */}
                      <Link
                        href={`/system/resources/${encodeURIComponent(resource.resourceId)}`}
                        className="block truncate font-mono text-xs text-[#001E2B] hover:underline"
                        title={resource.name}
                      >
                        {resource.name}
                      </Link>
                      {/*
                        * The human name sits under the key at every width rather than moving between
                        * columns as they drop away. Two names for one thing is the row's identity;
                        * reproducing it in whichever column happens to be visible is three places to
                        * keep right for no gain.
                        */}
                      {entry?.displayName && (
                        <span className="mt-0.5 block truncate text-xs text-gray-500" title={entry.displayName}>
                          {entry.displayName}
                        </span>
                      )}
                    </td>
                    <td className="hidden px-3 py-2 sm:table-cell">
                      <span className="block truncate text-xs text-gray-600" title={entry?.serverName}>
                        {entry?.serverName ?? '—'}
                      </span>
                    </td>
                    <td className="hidden px-3 py-2 lg:table-cell">
                      <span className="block text-xs text-gray-500">{entry?.description ?? '—'}</span>
                    </td>
                    <td className="hidden px-3 py-2 xl:table-cell">
                      <span className="block truncate font-mono text-xs text-gray-500" title={entry?.actions.join(', ')}>
                        {entry && entry.actions.length > 0 ? entry.actions.join(', ') : '—'}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <CatalogStatusBadge status={resource.status} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {!resources.loading && total > 0 && (
        <Pagination
          page={page}
          totalPages={Math.max(1, Math.ceil(total / limit))}
          total={total}
          limit={limit}
          noun="resources"
          onPageChange={setPage}
          onLimitChange={(next) => { setLimit(next); setPage(1); }}
        />
      )}
    </section>
  );
}

/**
 * Ask the authority what it would decide, right now.
 *
 * It calls the decision endpoint rather than re-implementing the rules in the browser, which is the
 * only way an answer here can be trusted: a simulator that reasons about the statements itself is a
 * second implementation, and the moment the two disagree the one on screen is the one nobody checks.
 *
 * Asking about somebody else is a separate authority at the API, because the answer describes what
 * THAT principal may do. The field defaults to the signed-in subject for the same reason.
 */
function Simulator({ policyId, subjectId }: { policyId: string; subjectId: string }) {
  const [subject, setSubject] = useState(subjectId);
  const [resource, setResource] = useState('roles');
  const [action, setAction] = useState('manage');
  const [assurance, setAssurance] = useState<'' | 'aal1' | 'aal2' | 'aal3'>('');
  const [ip, setIp] = useState('');
  const [attested, setAttested] = useState(false);
  const [result, setResult] = useState<DecisionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  async function evaluate() {
    setRunning(true);
    setError(null);
    try {
      setResult(await callApi<DecisionResult>('/decision', {
        method: 'POST',
        body: {
          ...(subject ? { subject: { type: 'identity', id: subject } } : {}),
          resource: { type: resource },
          action: { name: action },
          context: {
            ...(assurance ? { assuranceLevel: assurance } : {}),
            ...(ip ? { ip } : {}),
            ...(attested ? { attestationState: 'attested' } : {}),
          },
        },
        subject: 'that decision',
      }));
    } catch (failure) {
      setResult(null);
      setError(failure instanceof Error ? failure.message : 'That decision could not be evaluated.');
    } finally {
      setRunning(false);
    }
  }

  const decided = result?.context.policy;
  const thisPolicyDecided = decided?.policyId === policyId;

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <h2 className="font-semibold text-[#001E2B]">Try a request</h2>
      <p className="mt-0.5 text-sm text-gray-500">
        Answered by the authority itself, not by reading this page. It says what would be decided now:
        every evaluator, combined so that deny wins, and the rule that settled it.
      </p>

      <form
        onSubmit={(event) => { event.preventDefault(); void evaluate(); }}
        className="mt-3 space-y-3"
      >
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Principal" hint="Defaults to you. Asking about somebody else needs the permission that reads policies.">
            <input value={subject} onChange={(e) => setSubject(e.target.value)} className={INPUT} />
          </Field>
          <Field label="Resource">
            <input required value={resource} onChange={(e) => setResource(e.target.value)} className={INPUT} />
          </Field>
          <Field label="Action">
            <input required value={action} onChange={(e) => setAction(e.target.value)} className={INPUT} />
          </Field>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Assurance reached" hint="What the sign-in achieved, which a condition may require a floor for.">
            <select value={assurance} onChange={(e) => setAssurance(e.target.value as 'aal1')} className={INPUT}>
              <option value="">not stated</option>
              {ASSURANCE_LEVELS.map((level) => <option key={level} value={level}>{level}</option>)}
            </select>
          </Field>
          <Field label="Address" hint="Matched against an address prefix condition, literally.">
            <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.0.4" className={INPUT} />
          </Field>
          <Field label="Attested">
            <select value={attested ? 'yes' : 'no'} onChange={(e) => setAttested(e.target.value === 'yes')} className={INPUT}>
              <option value="no">no</option>
              <option value="yes">yes</option>
            </select>
          </Field>
        </div>

        <button
          type="submit"
          disabled={running || !resource || !action}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Play size={12} aria-hidden />
          {running ? 'Evaluating…' : 'Evaluate'}
        </button>
      </form>

      {error && <div className="mt-3"><ErrorState message={error} onRetry={() => void evaluate()} /></div>}

      {result && (
        <div className="mt-4 space-y-3 rounded-lg border border-gray-100 bg-gray-50/60 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <EffectBadge effect={result.context.effect} />
            <span className="text-sm text-gray-700">{result.context.reason}</span>
          </div>

          <p className="text-xs text-gray-500">
            {decided
              ? (
                <>
                  Decided by{' '}
                  <Link href={`/system/policies/${encodeURIComponent(decided.policyId)}`} className="font-medium text-[#001E2B] hover:underline">
                    {decided.name}
                  </Link>{' '}
                  at version {decided.version}
                  {thisPolicyDecided ? ', which is this policy.' : ', which is a different policy in this realm.'}
                </>
              )
              : result.context.source === 'default-deny'
                ? 'No policy and no role had an opinion, so the default applied. An absent decision is not an allow.'
                : `Decided by ${result.context.source ?? 'an evaluator'} rather than by a stored policy.`}
          </p>

          <div>
            <h3 className="text-[10px] uppercase tracking-wider text-gray-400">What each evaluator said alone</h3>
            <ul className="mt-1 space-y-1">
              {result.context.evaluators.map((opinion) => (
                <li key={opinion.name} className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="w-12 shrink-0 font-mono text-gray-500">{opinion.name}</span>
                  {opinion.effect
                    ? <EffectBadge effect={opinion.effect} />
                    : (
                      <Tooltip text="No opinion, which is not a denial. An evaluator with nothing to say must not override the one that has something to say.">
                        <span className="rounded border border-gray-200 bg-white px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-400">
                          no opinion
                        </span>
                      </Tooltip>
                    )}
                  <span className="min-w-0 truncate text-gray-500">{opinion.reason ?? ''}</span>
                </li>
              ))}
            </ul>
          </div>

          <p className="text-[11px] text-gray-400">
            Evaluated {when(result.context.evaluatedAt)}. This answers what the authority would decide;
            it changes nothing and grants nothing.
          </p>
        </div>
      )}
    </section>
  );
}
