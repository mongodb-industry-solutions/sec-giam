'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Code2, ListChecks, Play, Plus, Power, Save, Scale, Trash2, X } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { ErrorState, LoadingState } from '../../../../components/ResultState';
import { ActionButton, Fact } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { Field, INPUT } from '../../roles/parts';
import type { CatalogPermission, RoleSummary } from '../../roles/types';
import {
  EffectBadge, PatternList, PermissionChecklist, ResourceFields, StatusBadge,
  describeCondition, describeResource, splitPatterns,
} from '../parts';
import {
  ASSURANCE_LEVELS, CONDITION_KEYS,
  type ConditionKey, type DecisionResult, type PolicyCondition, type PolicyDetail,
} from '../types';

/**
 * One policy: what it states, and what it actually decides.
 *
 * The simulator is why this screen is worth having. A policy editor with no way to test a rule is
 * exactly how a deny gets written wrong and stays wrong: the rule looks right, nothing appears to
 * break, and the first time anybody finds out is when somebody is refused something they needed or
 * granted something they should not have had. Writing and testing belong on one screen.
 */

export default function PolicyDetailPage() {
  const params = useParams<{ policyId: string }>();
  const router = useRouter();
  const policyId = decodeURIComponent(String(params.policyId));

  const claims = currentClaims();
  const mayManage = can(claims, 'policies', 'manage');

  const read = useCallback(
    () => callApi<PolicyDetail>(`/policies/${encodeURIComponent(policyId)}`, { subject: 'that policy' }),
    [policyId],
  );
  const policy = useConsoleResource(read, 'That policy could not be read.');
  const [editing, setEditing] = useState(false);

  async function save(patch: Record<string, unknown>) {
    const done = await policy.run(
      'save',
      () => callApi(`/policies/${encodeURIComponent(policyId)}`, { method: 'PATCH', body: patch, subject: 'that policy' }),
      'That policy could not be changed.',
    );
    if (done) setEditing(false);
  }

  async function remove() {
    if (!window.confirm('Remove this policy? Removing one that denies widens access immediately, and this cannot be undone. Retiring it is reversible.')) return;
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
      <Link href="/system/policies" className="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500 hover:text-[#001E2B]">
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
              <ActionButton icon={Save} label={editing ? 'Stop editing' : 'Edit'} onClick={() => setEditing((was) => !was)} />
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
              </section>

              {editing && mayManage
                ? <PolicyEditor detail={detail} busy={policy.busy === 'save'} onSave={save} onCancel={() => setEditing(false)} />
                : <PolicyStatement detail={detail} />}

              <Simulator policyId={detail.policyId} subjectId={claims?.sub ?? ''} />
            </>
          )}
    </main>
  );
}

/** The rule as it will be read: effect first, then what it matches, then why. */
function PolicyStatement({ detail }: { detail: PolicyDetail }) {
  return (
    <section className="space-y-3">
      <div>
        <h2 className="font-semibold text-[#001E2B]">What it states</h2>
        <p className="mt-0.5 text-sm text-gray-500">
          Applies when every condition holds. A deny wins wherever else in the realm it sits.
        </p>
      </div>

      <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <EffectBadge effect={detail.effect} />
          <span className="font-mono text-xs text-gray-500">{describeResource(detail.resource)}</span>
        </div>

        <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
          <PatternList label="Permissions" values={detail.permissions} />
          <PatternList label="Principals" values={detail.principals} />
        </dl>

        {detail.conditions.length > 0 && detail.conditions.map((condition, index) => (
          describeCondition(condition).length > 0 && (
            <p key={index} className="mt-3 text-sm text-gray-600">
              Only when {describeCondition(condition).join(', and ')}.
            </p>
          )
        ))}

        {detail.obligations?.length ? (
          <PatternList label="Obligations" values={detail.obligations.map((o) => o.type)} />
        ) : null}

        {detail.reason && (
          <p className="mt-3 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">{detail.reason}</p>
        )}
      </div>
    </section>
  );
}

/**
 * Editing the one rule, with a condition editor that cannot express anything else.
 *
 * The five conditions are the whole vocabulary and there is no free-text alternative anywhere on the
 * form. That is not a convenience: it is the boundary that keeps this an identity authority. A
 * condition naming a monetary threshold, or any other business materiality, would be a judgement
 * about inputs this service cannot see. The API refuses one too, so the constraint holds even for a
 * caller that never opens this page.
 */
function PolicyEditor({ detail, busy, onSave, onCancel }: {
  detail: PolicyDetail;
  busy: boolean;
  onSave: (patch: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const [effect, setEffect] = useState(detail.effect);
  const [resourceMode, setResourceMode] = useState<'names' | 'pattern'>(detail.resource.pattern ? 'pattern' : 'names');
  const [resourceNames, setResourceNames] = useState((detail.resource.names ?? []).join(', '));
  const [resourcePattern, setResourcePattern] = useState(detail.resource.pattern ?? '');
  const [permissions, setPermissions] = useState((detail.permissions ?? []).join(', '));
  const [principals, setPrincipals] = useState((detail.principals ?? []).join(', '));
  const [reason, setReason] = useState(detail.reason ?? '');
  const [condition, setCondition] = useState<PolicyCondition | undefined>(detail.conditions[0]);

  function changeCondition(patch: PolicyCondition | undefined) {
    setCondition(patch === undefined || Object.keys(patch).length === 0 ? undefined : patch);
  }

  // Fetched here rather than at the page level: only an editing screen needs a role, a permission
  // and a resource to pick from, and this component only exists while one is open.
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
  const readResources = useCallback(
    () => callApi<{ resourceServers: Array<{ resources: Array<{ name: string }> }> }>('/resource-servers', { query: { limit: 200 }, subject: 'the resource server catalog' }),
    [],
  );
  const resourceServers = useConsoleResource(readResources, 'The resource server catalog could not be read.');
  useEffect(() => {
    void catalog.reload(); void allRoles.reload(); void resourceServers.reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const resourceCatalog = [...new Set(
    (resourceServers.data?.resourceServers ?? []).flatMap((server) => server.resources.map((entry) => entry.name)),
  )].sort();

  function buildPatch(): Record<string, unknown> {
    // A role or permission checkbox toggled on and then fully unchecked leaves an empty array
    // behind rather than removing the key; stripped here so the request never carries a condition
    // that could never hold.
    const sent = condition
      ? Object.fromEntries(Object.entries(condition).filter(([, value]) => !(Array.isArray(value) && value.length === 0)))
      : undefined;
    return {
      effect,
      resource: resourceMode === 'names' ? { names: splitPatterns(resourceNames) } : { pattern: resourcePattern },
      permissions: splitPatterns(permissions),
      ...(principals.trim() ? { principals: splitPatterns(principals) } : { principals: [] }),
      conditions: sent && Object.keys(sent).length > 0 ? [sent] : [],
      ...(reason.trim() ? { reason: reason.trim() } : {}),
    };
  }

  const [mode, setMode] = useState<'form' | 'json'>('form');
  const [json, setJson] = useState('');
  const [jsonError, setJsonError] = useState<string | null>(null);

  function enterJsonMode() {
    setJson(JSON.stringify(buildPatch(), null, 2));
    setJsonError(null);
    setMode('json');
  }

  /** Best-effort: what was typed becomes the form's own fields, so switching back loses nothing. */
  function enterFormMode() {
    try {
      const parsed = JSON.parse(json) as {
        effect?: 'allow' | 'deny'; resource?: { names?: string[]; pattern?: string };
        permissions?: string[]; principals?: string[]; reason?: string; conditions?: PolicyCondition[];
      };
      if (parsed.effect === 'allow' || parsed.effect === 'deny') setEffect(parsed.effect);
      const resource = parsed.resource ?? {};
      if (resource.pattern) { setResourceMode('pattern'); setResourcePattern(resource.pattern); } else {
        setResourceMode('names');
        setResourceNames((resource.names ?? []).join(', '));
      }
      setPermissions((parsed.permissions ?? []).join(', '));
      setPrincipals((parsed.principals ?? []).join(', '));
      setReason(parsed.reason ?? '');
      setCondition(parsed.conditions?.[0]);
      setJsonError(null);
      setMode('form');
    } catch {
      setJsonError('This is not valid JSON. Fix it, or cancel to discard these changes.');
    }
  }

  let jsonParseError: string | null = null;
  if (mode === 'json') {
    try { JSON.parse(json); } catch { jsonParseError = 'This is not valid JSON.'; }
  }

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
        <h2 className="font-semibold text-[#001E2B]">Edit what it states</h2>
        <div className="flex gap-1 text-xs">
          <button
            type="button"
            onClick={() => { if (mode === 'json') enterFormMode(); }}
            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium ${mode === 'form' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-500 hover:text-gray-700'}`}
          >
            <ListChecks size={12} aria-hidden />
            Form
          </button>
          <button
            type="button"
            onClick={() => { if (mode === 'form') enterJsonMode(); }}
            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-medium ${mode === 'json' ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]' : 'border-gray-200 text-gray-500 hover:text-gray-700'}`}
          >
            <Code2 size={12} aria-hidden />
            JSON
          </button>
        </div>
      </div>

      {mode === 'json' ? (
        <div className="space-y-2">
          <p className="text-xs text-gray-500">
            The same document `PATCH /realms/:realm/policies/:policyId` accepts, edited directly.
            Switching back to the form parses this; an invalid document stays here until it is valid JSON.
          </p>
          <textarea
            value={json}
            onChange={(e) => { setJson(e.target.value); setJsonError(null); }}
            rows={16}
            spellCheck={false}
            className="w-full rounded-lg border border-gray-200 bg-gray-50 p-3 font-mono text-xs text-gray-800 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
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
            <Field label="Principals" hint="Comma separated. Empty matches anyone. A trailing * matches a prefix.">
              <input value={principals} onChange={(e) => setPrincipals(e.target.value)} className={INPUT} />
            </Field>
          </div>

          <Field label="Permissions" hint="Comma separated, full resource:action strings. Or check them below; a wildcard has no box to check, so typing stays the way to reach one.">
            <input required value={permissions} onChange={(e) => setPermissions(e.target.value)} className={INPUT} />
          </Field>
          <PermissionChecklist value={permissions} onChange={setPermissions} catalog={catalog.data?.permissions ?? []} />

          <ResourceFields
            mode={resourceMode}
            onModeChange={setResourceMode}
            names={resourceNames}
            onNamesChange={setResourceNames}
            pattern={resourcePattern}
            onPatternChange={setResourcePattern}
            catalog={resourceCatalog}
          />

          <ConditionEditor
            condition={condition}
            onChange={changeCondition}
            roles={allRoles.data?.roles ?? []}
            permissions={catalog.data?.permissions ?? []}
          />

          <Field label="Reason" hint="Carried into the decision. Write what a reader should understand months from now.">
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} rows={2} className={INPUT} />
          </Field>
        </>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy || (mode === 'json'
            ? Boolean(jsonParseError)
            : !permissions.trim() || !(resourceMode === 'names' ? resourceNames.trim() : resourcePattern.trim()))}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Saving…' : 'Save'}
        </button>
        <ActionButton icon={X} label="Cancel" onClick={onCancel} />
      </div>
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
