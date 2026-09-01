'use client';

import { useCallback, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Minus, Play, Plus, Power, Save, Scale, Trash2 } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { ErrorState, LoadingState } from '../../../../components/ResultState';
import { ActionButton, Fact } from '../../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../../lib/console';
import { useConsoleResource } from '../../../../lib/useConsoleResource';
import { Field, INPUT } from '../../roles/parts';
import { DisabledBadge, EffectBadge, PatternList, describeCondition } from '../parts';
import {
  ASSURANCE_LEVELS, CONDITION_KEYS,
  type ConditionKey, type DecisionResult, type PolicyCondition, type PolicyDetail, type PolicyStatement,
} from '../types';

/**
 * One policy: what it states, and what it actually decides.
 *
 * The simulator is why this screen is worth having. A policy editor with no way to test a rule is
 * exactly how a deny gets written wrong and stays wrong: the statement looks right, nothing appears
 * to break, and the first time anybody finds out is when somebody is refused something they needed
 * or granted something they should not have had. Writing and testing belong on one screen.
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
    if (!window.confirm('Remove this policy? Removing one that denies widens access immediately, and this cannot be undone. Disabling it is reversible.')) return;
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
              <ActionButton
                icon={Power}
                label={detail.enabled ? 'Disable' : 'Enable'}
                busy={policy.busy === 'toggle'}
                onClick={() => void policy.run(
                  'toggle',
                  () => callApi(`/policies/${encodeURIComponent(policyId)}`, {
                    method: 'PATCH', body: { enabled: !detail.enabled }, subject: 'that policy',
                  }),
                  'That policy could not be switched.',
                )}
              />
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
                  {detail.denyCount > 0 && <EffectBadge effect="deny" />}
                  {!detail.enabled && <DisabledBadge />}
                </div>
                <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-4">
                  <Fact label="Statements" value={`${detail.statementCount}`} />
                  <Fact label="Prohibiting" value={`${detail.denyCount}`} />
                  <Fact label="Conditional" value={`${detail.conditionCount}`} />
                  <Fact label="Last changed" value={when(detail.lastModified)} />
                </dl>
                {!detail.enabled && (
                  <p className="mt-3 border-l-2 border-amber-200 pl-2.5 text-sm text-gray-600">
                    Switched off, so none of these statements decides anything. The simulator below
                    reflects that: it asks the authority rather than reading this document.
                  </p>
                )}
              </section>

              {editing && mayManage
                ? <StatementsEditor detail={detail} busy={policy.busy === 'save'} onSave={save} onCancel={() => setEditing(false)} />
                : <StatementList statements={detail.statements} />}

              <Simulator policyId={detail.policyId} subjectId={claims?.sub ?? ''} />
            </>
          )}
    </main>
  );
}

/** The statements as they will be read: effect first, then what they match, then why. */
function StatementList({ statements }: { statements: PolicyStatement[] }) {
  return (
    <section className="space-y-3">
      <div>
        <h2 className="font-semibold text-[#001E2B]">What it states</h2>
        <p className="mt-0.5 text-sm text-gray-500">
          A statement applies when every pattern it names matches and its condition holds. Order does
          not change the outcome, because a deny wins wherever it sits.
        </p>
      </div>

      <ul className="space-y-3">
        {statements.map((statement, index) => (
          <li key={index} className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
            <div className="flex flex-wrap items-center gap-2">
              <EffectBadge effect={statement.effect} />
              <span className="font-mono text-xs text-gray-400">statement {index + 1}</span>
            </div>

            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3">
              <PatternList label="Principals" values={statement.principals} />
              <PatternList label="Resources" values={statement.resources} />
              <PatternList label="Actions" values={statement.actions} />
            </dl>

            {statement.condition && describeCondition(statement.condition).length > 0 && (
              <p className="mt-3 text-sm text-gray-600">
                Only when {describeCondition(statement.condition).join(', and ')}.
              </p>
            )}

            {statement.reason && (
              <p className="mt-3 border-l-2 border-gray-200 pl-2.5 text-sm italic text-gray-600">{statement.reason}</p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * Editing the statements, with a condition editor that cannot express anything else.
 *
 * The five conditions are the whole vocabulary and there is no free-text alternative anywhere on the
 * form. That is not a convenience: it is the boundary that keeps this an identity authority. A
 * condition naming a monetary threshold, or any other business materiality, would be a judgement
 * about inputs this service cannot see. The API refuses one too, so the constraint holds even for a
 * caller that never opens this page.
 */
function StatementsEditor({ detail, busy, onSave, onCancel }: {
  detail: PolicyDetail;
  busy: boolean;
  onSave: (patch: Record<string, unknown>) => void;
  onCancel: () => void;
}) {
  const [version, setVersion] = useState(detail.version);
  const [statements, setStatements] = useState<PolicyStatement[]>(() => structuredClone(detail.statements));

  function change(index: number, patch: Partial<PolicyStatement>) {
    setStatements((was) => was.map((statement, position) => (position === index ? { ...statement, ...patch } : statement)));
  }

  function changeCondition(index: number, patch: PolicyCondition | undefined) {
    setStatements((was) => was.map((statement, position) => {
      if (position !== index) return statement;
      const next = { ...statement };
      if (patch === undefined || Object.keys(patch).length === 0) delete next.condition;
      else next.condition = patch;
      return next;
    }));
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        onSave({ version, statements });
      }}
      className="space-y-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <h2 className="font-semibold text-[#001E2B]">Edit what it states</h2>

      <Field label="Version" hint="Named in every decision this policy makes. Move it when the meaning changes.">
        <input value={version} onChange={(e) => setVersion(e.target.value)} className={INPUT} />
      </Field>

      <ul className="space-y-4">
        {statements.map((statement, index) => (
          <li key={index} className="rounded-lg border border-gray-100 bg-gray-50/60 p-3">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-xs text-gray-400">statement {index + 1}</span>
              {statements.length > 1 && (
                <button
                  type="button"
                  onClick={() => setStatements((was) => was.filter((_, position) => position !== index))}
                  className="text-xs font-medium text-red-600 hover:underline"
                >
                  Remove
                </button>
              )}
            </div>

            <div className="mt-2 grid gap-3 sm:grid-cols-2">
              <Field label="Effect" hint="Deny wins over every allow in the realm.">
                <select
                  value={statement.effect}
                  onChange={(e) => change(index, { effect: e.target.value as 'allow' | 'deny' })}
                  className={INPUT}
                >
                  <option value="allow">Allow</option>
                  <option value="deny">Deny</option>
                </select>
              </Field>
              <Field label="Principals" hint="Comma separated. Empty matches anyone. A trailing * matches a prefix.">
                <input
                  value={(statement.principals ?? []).join(', ')}
                  onChange={(e) => change(index, { principals: splitPatterns(e.target.value) })}
                  className={INPUT}
                />
              </Field>
              <Field label="Resources" hint="Comma separated. Empty matches anything.">
                <input
                  value={(statement.resources ?? []).join(', ')}
                  onChange={(e) => change(index, { resources: splitPatterns(e.target.value) })}
                  className={INPUT}
                />
              </Field>
              <Field label="Actions" hint="Comma separated. Empty matches anything.">
                <input
                  value={(statement.actions ?? []).join(', ')}
                  onChange={(e) => change(index, { actions: splitPatterns(e.target.value) })}
                  className={INPUT}
                />
              </Field>
            </div>

            <ConditionEditor
              condition={statement.condition}
              onChange={(next) => changeCondition(index, next)}
            />

            <Field label="Reason" hint="Carried into the decision. Write what a reader should understand months from now.">
              <textarea
                value={statement.reason ?? ''}
                onChange={(e) => change(index, { reason: e.target.value })}
                rows={2}
                className={INPUT}
              />
            </Field>
          </li>
        ))}
      </ul>

      <ActionButton
        icon={Plus}
        label="Add a statement"
        onClick={() => setStatements((was) => [...was, { effect: 'allow' }])}
      />

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Saving…' : 'Save statements'}
        </button>
        <ActionButton icon={Minus} label="Cancel" onClick={onCancel} />
      </div>
    </form>
  );
}

function splitPatterns(value: string): string[] {
  return value.split(',').map((entry) => entry.trim()).filter(Boolean);
}

/**
 * The closed condition set, and nothing else.
 *
 * Each of the five is a checkbox with its own control. There is no free-text row and no "other",
 * which is the whole point: what a policy may say about a request is what this authority can
 * actually observe about the identity making it.
 */
function ConditionEditor({ condition, onChange }: {
  condition?: PolicyCondition;
  onChange: (next: PolicyCondition | undefined) => void;
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
    };
    set(key, on ? defaults[key] : undefined);
  }

  const labels: Record<ConditionKey, string> = {
    assuranceAtLeast: 'Assurance at least',
    ipInRange: 'Address starts with',
    timeOfDayUtc: 'Hour of day (UTC)',
    tenantIs: 'Tenant is',
    attestationRequired: 'Attestation required',
  };

  return (
    <fieldset className="mt-3">
      <legend className="text-xs font-medium text-gray-600">Condition</legend>
      <Tooltip text="Identity context only, and this list is all of it. A condition naming a business threshold would be a judgement about inputs this authority cannot observe, so there is no way to write one.">
        <p className="mt-0.5 text-[11px] text-gray-400">
          Assurance, network, time, tenant and attestation. There is nothing else a policy may say.
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
        every evaluator, combined so that deny wins, and the statement that settled it.
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
                  Decided by statement {decided.statementIndex + 1} of{' '}
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
