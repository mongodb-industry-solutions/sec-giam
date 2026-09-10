'use client';

import { Tooltip } from '../../../components/Tooltip';
import { Field, INPUT } from '../roles/parts';
import type { CatalogPermission } from '../roles/types';
import type { PolicyCondition, PolicyResource } from './types';

/** The small pieces both policy screens use. Kept out of the pages so neither owns the other's shape. */

/**
 * Allow or deny, and they are not symmetrical.
 *
 * Deny wins over every allow anywhere in the realm, so the two badges are deliberately not two
 * shades of the same thing: a reader scanning a list has to be able to see which statements can
 * withhold something.
 */
export function EffectBadge({ effect }: { effect: 'allow' | 'deny' }) {
  return (
    <Tooltip text={effect === 'deny'
      ? 'Wins over every allow, in this policy and in every other. Nothing overturns it.'
      : 'Permits, unless something anywhere in the realm denies the same request.'}>
      <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
        effect === 'deny' ? 'border-red-200 bg-red-50 text-red-700' : 'border-emerald-200 bg-emerald-50 text-emerald-700'
      }`}>
        {effect}
      </span>
    </Tooltip>
  );
}

/** The three states a policy's own record can be in, distinct from whether it decides anything today. */
export function StatusBadge({ status }: { status: 'draft' | 'active' | 'retired' }) {
  if (status === 'active') return null;
  return (
    <Tooltip text={status === 'draft'
      ? 'Written down but never switched on. It decides nothing until its status changes to active.'
      : 'Withdrawn. Kept for the record rather than deleted, and it decides nothing while retired.'}>
      <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
        {status}
      </span>
    </Tooltip>
  );
}

/** A pattern list, or the plain statement that it matches everything. Silence would read as neither. */
export function PatternList({ label, values }: { label: string; values?: string[] }) {
  const text = values?.length ? values.join(', ') : 'anything';
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className={`truncate ${values?.length ? 'font-mono text-gray-700' : 'italic text-gray-400'}`} title={text}>
        {text}
      </dd>
    </div>
  );
}

/** A condition rendered as the sentence it means, because a JSON fragment is not something to review. */
export function describeCondition(condition: PolicyCondition): string[] {
  const parts: string[] = [];
  if (condition.assuranceAtLeast) parts.push(`the sign-in reached ${condition.assuranceAtLeast} or stronger`);
  if (condition.ipInRange?.length) parts.push(`the address starts with ${condition.ipInRange.join(' or ')}`);
  if (condition.timeOfDayUtc) {
    const { from, to } = condition.timeOfDayUtc;
    parts.push(from <= to
      ? `the hour is between ${from}:00 and ${to}:00 UTC`
      : `the hour is after ${from}:00 or before ${to}:00 UTC`);
  }
  if (condition.tenantIs) parts.push(`the request is inside tenant ${condition.tenantIs}`);
  if (condition.attestationRequired) parts.push('the caller arrived attested');
  if (condition.heldRole?.length) parts.push(`the subject already holds one of these roles: ${condition.heldRole.join(', ')}`);
  if (condition.heldPermission?.length) parts.push(`the subject already holds every one of these permissions: ${condition.heldPermission.join(', ')}`);
  return parts;
}

/** What a policy governs, read as a sentence: named exactly, or by pattern. Never both, per the contract. */
export function describeResource(resource: PolicyResource): string {
  if (resource.names?.length) return `named exactly: ${resource.names.join(', ')}`;
  if (resource.pattern) return `matching the pattern ${resource.pattern}`;
  return 'unspecified';
}

/** Every field on this screen that takes "one or several" holds them the same way: comma separated. */
export function splitPatterns(value: string): string[] {
  return value.split(',').map((entry) => entry.trim()).filter(Boolean);
}

/** Adds or removes one value from a comma-separated field, without disturbing anything typed by hand. */
function toggleCsv(current: string, value: string, checked: boolean): string {
  const values = splitPatterns(current);
  const next = checked ? [...new Set([...values, value])] : values.filter((entry) => entry !== value);
  return next.join(', ');
}

/**
 * Which resource a policy governs, exact names or a regular expression. Shared by the create form
 * and the detail page's editor, so the two cannot drift into offering the choice differently.
 *
 * `catalog`, when given, offers every resource this realm's own resource servers have actually
 * declared as checkboxes alongside the free-text field: the common case is picking one that already
 * exists, and typing remains for a resource not registered yet, or a realm with none to offer.
 */
export function ResourceFields({ mode, onModeChange, names, onNamesChange, pattern, onPatternChange, catalog }: {
  mode: 'names' | 'pattern';
  onModeChange: (mode: 'names' | 'pattern') => void;
  names: string;
  onNamesChange: (value: string) => void;
  pattern: string;
  onPatternChange: (value: string) => void;
  catalog?: string[];
}) {
  const selected = new Set(splitPatterns(names));
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Resource, by" hint="Exact names are a fast, indexed lookup. A pattern is a regular expression, compiled with RE2 so it cannot hang a decision, evaluated only against the policies that chose it.">
          <select value={mode} onChange={(e) => onModeChange(e.target.value as 'names' | 'pattern')} className={INPUT}>
            <option value="names">Exact name(s)</option>
            <option value="pattern">Pattern (regular expression)</option>
          </select>
        </Field>
        {mode === 'names' ? (
          <Field label="Resource name(s)" hint="Comma separated, e.g. roles, sessions. Or check them below.">
            <input required value={names} onChange={(e) => onNamesChange(e.target.value)} className={INPUT} placeholder="roles" />
          </Field>
        ) : (
          <Field label="Pattern" hint="A regular expression (RE2 syntax), matched against the resource name.">
            <input required value={pattern} onChange={(e) => onPatternChange(e.target.value)} className={INPUT} placeholder="^reports.*" />
          </Field>
        )}
      </div>

      {mode === 'names' && catalog && catalog.length > 0 && (
        <div className="max-h-40 overflow-y-auto rounded-lg border border-gray-200 p-2">
          {catalog.map((name) => (
            <label key={name} className="flex items-center gap-1.5 py-0.5 text-xs text-gray-700">
              <input
                type="checkbox"
                checked={selected.has(name)}
                onChange={(e) => onNamesChange(toggleCsv(names, name, e.target.checked))}
                className="rounded border-gray-300"
              />
              <span className="font-mono">{name}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * Every `resource:action` this realm's catalog declares, as checkboxes toggling the same
 * comma-separated field a caller can also type into directly: wildcards (`roles:*`, `*`) have no
 * catalog entry to check, so free text stays the only way to reach them.
 */
export function PermissionChecklist({ value, onChange, catalog }: {
  value: string;
  onChange: (next: string) => void;
  catalog: CatalogPermission[];
}) {
  const selected = new Set(splitPatterns(value));
  if (catalog.length === 0) return null;
  return (
    <div className="max-h-40 overflow-y-auto rounded-lg border border-gray-200 p-2">
      {catalog.map((permission) => {
        const key = `${permission.resource}:${permission.action}`;
        return (
          <label key={key} className="flex items-center gap-1.5 py-0.5 text-xs text-gray-700">
            <input
              type="checkbox"
              checked={selected.has(key)}
              onChange={(e) => onChange(toggleCsv(value, key, e.target.checked))}
              className="rounded border-gray-300"
            />
            <span className="font-mono">{key}</span>
          </label>
        );
      })}
    </div>
  );
}
