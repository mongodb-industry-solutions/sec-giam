'use client';

import { useState } from 'react';
import { Search, X } from 'lucide-react';
import { Tooltip } from '../../../components/Tooltip';
import { Field, INPUT } from '../roles/parts';
import type { CatalogPermission } from '../roles/types';
import type { PolicyCondition, Selector } from './types';

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

/**
 * A selector read as a sentence: named exactly, by pattern, or (for an optional one, like
 * `principal`) absent. `ids` wins over `pattern` in what actually decides, so an id list is shown
 * first and a pattern beside it is described as unused rather than combined.
 */
export function describeSelector(selector: Selector | undefined, whenAbsent = 'unspecified'): string {
  if (selector?.ids?.length) {
    return selector.pattern
      ? `named exactly: ${selector.ids.join(', ')} (a pattern is also set, ${selector.pattern}, but ids win and it decides nothing)`
      : `named exactly: ${selector.ids.join(', ')}`;
  }
  if (selector?.pattern) return `matching the pattern ${selector.pattern}`;
  return whenAbsent;
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
 * One thing that can be picked: the id a policy stores, and what it is called for a reader.
 *
 * The id is the value, always: a policy stores `sessions`, and no presentation changes that. The
 * label and the group are what make an exact choice possible without already knowing the catalog by
 * heart, which is what a bare list of camelCase keys demanded.
 */
export interface CatalogOption {
  id: string;
  label?: string;
  /** The resource server, or whatever these belong to. Shown as a heading, and searchable. */
  group?: string;
}

/**
 * Picking exact ids out of a catalog: searchable, grouped, and showing what is already chosen.
 *
 * The list used to be every id at once, unlabelled and unsearchable, four rows tall, with a
 * comma-separated text field above it as the real control. Adding one existing resource meant
 * scrolling dozens of keys looking for the right spelling, and nothing on screen confirmed what was
 * already named. So what is selected comes first, as chips that can be removed one at a time; the
 * search narrows on the id, the label and the server; and each row shows the id it will store
 * beside the name a person recognises.
 */
function CatalogPicker({ noun, catalog, ids, onIdsChange }: {
  noun: string;
  catalog: CatalogOption[];
  ids: string;
  onIdsChange: (value: string) => void;
}) {
  const [query, setQuery] = useState('');
  const chosen = splitPatterns(ids);
  const selected = new Set(chosen);
  const known = new Map(catalog.map((option) => [option.id, option] as const));

  const needle = query.trim().toLowerCase();
  const matching = needle
    ? catalog.filter((option) => `${option.id} ${option.label ?? ''} ${option.group ?? ''}`.toLowerCase().includes(needle))
    : catalog;

  // Grouped by whoever declares each one: the same short name can be declared by more than one
  // resource server, and the group is the only thing that tells those apart.
  const groups = new Map<string, CatalogOption[]>();
  for (const option of matching) {
    groups.set(option.group ?? '', [...(groups.get(option.group ?? '') ?? []), option]);
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-1.5">
        {chosen.length === 0
          ? <span className="text-xs text-gray-400">{`Nothing chosen yet. Search and tick the ${noun.toLowerCase()}s this policy names.`}</span>
          : chosen.map((id) => (
            <span
              key={id}
              title={known.get(id)?.label ?? id}
              className="inline-flex items-center gap-1 rounded-full bg-[#001E2B]/5 py-0.5 pl-2 pr-1 text-xs text-[#001E2B]"
            >
              <span className="font-mono">{id}</span>
              {!known.has(id) && (
                <span className="text-[10px] font-medium text-amber-700" title="Nothing in the catalog declares this">?</span>
              )}
              <button
                type="button"
                onClick={() => onIdsChange(toggleCsv(ids, id, false))}
                aria-label={`Remove ${id}`}
                className="rounded-full p-0.5 text-gray-400 transition-colors hover:bg-red-50 hover:text-red-600"
              >
                <X size={11} aria-hidden />
              </button>
            </span>
          ))}
        {chosen.length > 1 && (
          <button
            type="button"
            onClick={() => onIdsChange('')}
            className="ml-1 text-[11px] text-gray-400 hover:text-[#001E2B] hover:underline"
          >
            Clear all
          </button>
        )}
      </div>

      <div className="relative">
        <Search size={13} className="pointer-events-none absolute left-2.5 top-2.5 text-gray-400" aria-hidden />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={`Search ${noun.toLowerCase()}s by name`}
          aria-label={`Search ${noun.toLowerCase()}s`}
          className={`${INPUT} pl-7`}
        />
      </div>

      <div className="max-h-64 overflow-y-auto rounded-lg border border-gray-200 p-2">
        {matching.length === 0 && (
          <p className="px-1 py-2 text-xs text-gray-400">
            Nothing in the catalog matches that. A value it does not declare can still be typed in the field above.
          </p>
        )}
        {[...groups.entries()].map(([group, options]) => (
          <div key={group} className="mb-1.5 last:mb-0">
            {group && (
              <p className="px-1 py-0.5 text-[10px] font-medium uppercase tracking-wider text-gray-400">{group}</p>
            )}
            {options.map((option) => (
              <label
                key={`${group}:${option.id}`}
                className="flex cursor-pointer items-center gap-2 rounded px-1 py-1 text-xs text-gray-700 hover:bg-gray-50"
              >
                <input
                  type="checkbox"
                  checked={selected.has(option.id)}
                  onChange={(event) => onIdsChange(toggleCsv(ids, option.id, event.target.checked))}
                  className="rounded border-gray-300"
                />
                <span className="font-mono">{option.id}</span>
                {option.label && <span className="truncate text-gray-500">{option.label}</span>}
              </label>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * One selector: named ids or a regular expression, never edited as both at once even though the
 * contract now tolerates it (ids would just win). Shared by every section that is a {@link Selector}
 * — resource, permission, principal, role — so the four cannot drift into offering the choice
 * differently.
 *
 * `catalog`, when given, offers every value this realm already knows about (a resource type, a
 * declared permission, a role name) as checkboxes alongside the free-text field: the common case is
 * picking one that already exists, and typing remains for one not registered yet.
 */
export function SelectorFields({
  noun, mode, onModeChange, ids, onIdsChange, pattern, onPatternChange, catalog, required = true,
}: {
  /** What this selector names, for the field labels: "Resource", "Permission", "Principal", "Role". */
  noun: string;
  mode: 'ids' | 'pattern';
  onModeChange: (mode: 'ids' | 'pattern') => void;
  ids: string;
  onIdsChange: (value: string) => void;
  pattern: string;
  onPatternChange: (value: string) => void;
  catalog?: CatalogOption[];
  /** False for an optional selector (principal, role): leaving both fields empty is a valid choice. */
  required?: boolean;
}) {
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={`${noun}, by`} hint="Exact ids are a fast, indexed lookup. A pattern is a regular expression, compiled with RE2 so it cannot hang a decision. If both are given, ids wins and the pattern decides nothing.">
          <select value={mode} onChange={(e) => onModeChange(e.target.value as 'ids' | 'pattern')} className={INPUT}>
            <option value="ids">Exact id(s)</option>
            <option value="pattern">Pattern (regular expression)</option>
          </select>
        </Field>
        {mode === 'ids' ? (
          <Field label={`${noun} id(s)`} hint="What gets stored. Pick from the catalog below, or type a value it does not declare.">
            <input required={required} value={ids} onChange={(e) => onIdsChange(e.target.value)} className={`${INPUT} font-mono text-xs`} />
          </Field>
        ) : (
          <Field label="Pattern" hint={`A regular expression (RE2 syntax), matched against the ${noun.toLowerCase()}.`}>
            <input required={required} value={pattern} onChange={(e) => onPatternChange(e.target.value)} className={INPUT} placeholder="^reports.*" />
          </Field>
        )}
      </div>

      {mode === 'ids' && catalog && catalog.length > 0 && (
        <CatalogPicker noun={noun} catalog={catalog} ids={ids} onIdsChange={onIdsChange} />
      )}
    </div>
  );
}

/**
 * Every `resource:action` a realm's catalog declares, as options the picker can offer.
 *
 * Grouped by the resource server that enforces it and glossed in words, because `paymentInstruments:
 * viewSensitive` is not something to recognise from a flat list: the same action name appears on a
 * dozen resources, and which server enforces it is the part that decides whether it is the one
 * meant.
 */
export function permissionCatalogOptions(catalog: CatalogPermission[]): CatalogOption[] {
  return catalog
    .map((permission) => ({
      id: `${permission.resource}:${permission.action}`,
      label: permission.description ?? `${permission.action} on ${permission.resource}`,
      group: permission.resourceServer,
    }))
    .sort((left, right) => left.id.localeCompare(right.id));
}

/**
 * A resource's full name: the resource server that declares it, then the resource itself.
 *
 * ONE definition, used by every screen that names a resource, because a resource called "Roles"
 * says nothing on its own: the console has a roles section of its own, and several resource servers
 * may each declare a type under the same short name. What identifies it is the pair, so the pair is
 * the name, and it reads the same in a policy's list as it does in the heading of the resource's own
 * page.
 *
 * Falls back to the stored name when the catalog declares no display name, and to the stored name
 * alone when the declaring server is unknown, which is what a policy naming something withdrawn
 * looks like.
 */
export function resourceLabel(
  storedName: string,
  entry?: { displayName?: string; serverName?: string },
): string {
  const own = entry?.displayName ?? storedName;
  return entry?.serverName ? `${entry.serverName} / ${own}` : own;
}
