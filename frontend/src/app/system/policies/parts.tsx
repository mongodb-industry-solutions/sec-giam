'use client';

import { useState } from 'react';
import { ListToolbar } from '../../../components/ListToolbar';
import { Pagination } from '../../../components/Pagination';
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
 * One thing that can be chosen: the id a policy stores, and what it is called for a reader.
 *
 * The id is the value, always: a policy stores `sessions`, and no presentation changes that. The
 * rest is what makes an exact choice possible without knowing the catalog by heart.
 */
export interface CatalogOption {
  id: string;
  label?: string;
  /** Who declares it (the resource server, usually). A heading on wide screens, always searchable. */
  group?: string;
  /** One more fact worth a column: the actions a resource declares, a role's scope, a kind. */
  detail?: string;
}

type Membership = 'all' | 'chosen' | 'available';

/**
 * One selector, as the same panel every time: a list with search, a filter, paging, and a check
 * column that IS the choosing.
 *
 * Resource, permission, role and principal are the same question asked about four catalogs, so they
 * are one component rather than four arrangements of the same fields. What this replaced asked the
 * question two ways at once: a comma-separated text box as the real control, with an unlabelled,
 * unsearchable list of every id underneath it. Choosing one of forty meant knowing its spelling
 * already.
 *
 * Four columns at most, and fewer as the screen narrows: the check and the id are the row's whole
 * purpose so they never leave, the name follows from `sm`, who declares it from `lg`, and the last
 * fact from `xl`. A pattern is still a pattern: it names no fixed set, so there is nothing to tick
 * and the panel says so instead of pretending otherwise.
 */
export function SelectorPanel({
  noun, description, mode, onModeChange, ids, onIdsChange, pattern, onPatternChange,
  catalog, columns, required = true, loading = false, emptyCatalog, disabled = false,
}: {
  /** "Resource", "Permission", "Role", "Principal". Used for every label in here. */
  noun: string;
  description: string;
  mode: 'ids' | 'pattern';
  onModeChange: (mode: 'ids' | 'pattern') => void;
  /** Comma separated, which is how every one of these fields has always been stored. */
  ids: string;
  onIdsChange: (value: string) => void;
  pattern: string;
  onPatternChange: (value: string) => void;
  catalog?: CatalogOption[];
  /** Headings for the two optional columns, so each panel names its own facts. */
  columns?: { group?: string; detail?: string };
  /** False for an optional selector (role, principal): choosing nothing is a valid answer. */
  required?: boolean;
  loading?: boolean;
  /** What it means for this catalog to be empty, which is never just "no rows". */
  emptyCatalog?: string;
  /** A reader without the permission to change this: the same panel, nothing to tick. */
  disabled?: boolean;
}) {
  const [query, setQuery] = useState('');
  const [membership, setMembership] = useState<Membership>('all');
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(10);

  const chosen = splitPatterns(ids);
  const selected = new Set(chosen);
  const options = catalog ?? [];
  const known = new Set(options.map((option) => option.id));

  /**
   * Anything chosen that the catalog does not declare is still a row.
   *
   * A policy can name something withdrawn, or something registered after this list was read.
   * Dropping it from the table would hide part of what the policy says, and unticking it would then
   * be impossible; it is shown, marked, and removable like everything else.
   */
  const rows: Array<CatalogOption & { unregistered?: boolean }> = [
    ...chosen.filter((id) => !known.has(id)).map((id) => ({ id, unregistered: true })),
    ...options,
  ];

  const needle = query.trim().toLowerCase();
  const matching = rows.filter((row) => {
    if (membership === 'chosen' && !selected.has(row.id)) return false;
    if (membership === 'available' && selected.has(row.id)) return false;
    if (!needle) return true;
    return `${row.id} ${row.label ?? ''} ${row.group ?? ''} ${row.detail ?? ''}`.toLowerCase().includes(needle);
  });

  const total = matching.length;
  const shown = matching.slice((page - 1) * limit, page * limit);

  function setAll(values: string[]): void {
    onIdsChange([...new Set(values)].join(', '));
  }

  function toggle(id: string, checked: boolean): void {
    onIdsChange(toggleCsv(ids, id, checked));
  }

  const allShownChosen = shown.length > 0 && shown.every((row) => selected.has(row.id));

  return (
    <section className="space-y-2.5 rounded-xl border border-gray-200 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-[#001E2B]">
            {noun}
            <span className="rounded-full bg-[#001E2B]/5 px-1.5 py-0.5 text-[10px] font-medium text-[#001E2B]">
              {mode === 'pattern' ? 'by pattern' : `${chosen.length} chosen`}
            </span>
          </h3>
          <p className="mt-0.5 text-xs text-gray-500">{description}</p>
        </div>
        <label className="flex items-center gap-1.5 text-[11px] text-gray-500">
          <span className="sr-only sm:not-sr-only">Choose by</span>
          <select
            value={mode}
            onChange={(event) => onModeChange(event.target.value as 'ids' | 'pattern')}
            disabled={disabled}
            aria-label={`How this policy names ${noun.toLowerCase()}s`}
            className="rounded-lg border border-gray-200 px-2 py-1 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          >
            <option value="ids">Exact list</option>
            <option value="pattern">Pattern</option>
          </select>
        </label>
      </div>

      {mode === 'pattern' ? (
        <div className="space-y-1.5">
          <input
            required={required}
            value={pattern}
            onChange={(event) => onPatternChange(event.target.value)}
            readOnly={disabled}
            placeholder="^report.*"
            aria-label={`${noun} pattern`}
            className={`${INPUT} font-mono text-xs`}
          />
          <p className="text-[11px] text-gray-400">
            A regular expression (RE2 syntax), matched live at decision time. It names no fixed set,
            so there is nothing to tick here; what it currently reaches is resolved by the authority.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          <ListToolbar
            search={{
              value: query,
              onChange: (next) => { setQuery(next); setPage(1); },
              placeholder: `Search ${noun.toLowerCase()}s`,
              label: `Search ${noun.toLowerCase()}s`,
            }}
            filter={{
              label: `Show ${noun.toLowerCase()}s`,
              value: membership,
              onChange: (next: Membership) => { setMembership(next); setPage(1); },
              options: [
                { key: 'all' as Membership, label: 'All' },
                { key: 'chosen' as Membership, label: `Chosen (${chosen.length})` },
                { key: 'available' as Membership, label: 'Not chosen' },
              ],
            }}
            extra={(
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setAll(allShownChosen
                    ? chosen.filter((id) => !shown.some((row) => row.id === id))
                    : [...chosen, ...shown.map((row) => row.id)])}
                  disabled={disabled || shown.length === 0}
                  className="rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:border-[#001E2B] hover:text-[#001E2B] disabled:opacity-40"
                >
                  {allShownChosen ? 'Unpick these' : 'Pick these'}
                </button>
                {chosen.length > 0 && !disabled && (
                  <button
                    type="button"
                    onClick={() => onIdsChange('')}
                    className="text-xs text-gray-400 transition-colors hover:text-[#001E2B] hover:underline"
                  >
                    Clear all
                  </button>
                )}
              </div>
            )}
          />

          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full table-fixed text-left text-sm">
              <thead className="bg-gray-50 text-[10px] uppercase tracking-wider text-gray-400">
                <tr>
                  <th scope="col" className="w-9 px-2 py-2">
                    <span className="sr-only">Chosen</span>
                  </th>
                  <th scope="col" className="px-2 py-2 font-medium">{noun}</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium sm:table-cell sm:w-1/3">Name</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium lg:table-cell lg:w-1/4">{columns?.group ?? 'Declared by'}</th>
                  {columns?.detail && (
                    <th scope="col" className="hidden px-2 py-2 font-medium xl:table-cell xl:w-1/5">{columns.detail}</th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {shown.map((row) => (
                  <tr key={row.id} className={`align-top ${selected.has(row.id) ? 'bg-[#00ED64]/5' : 'hover:bg-gray-50'}`}>
                    <td className="px-2 py-1.5">
                      <input
                        type="checkbox"
                        checked={selected.has(row.id)}
                        onChange={(event) => toggle(row.id, event.target.checked)}
                        disabled={disabled}
                        aria-label={`${selected.has(row.id) ? 'Remove' : 'Add'} ${row.id}`}
                        className="rounded border-gray-300"
                      />
                    </td>
                    <td className="px-2 py-1.5">
                      <span className="block truncate font-mono text-xs text-[#001E2B]" title={row.id}>{row.id}</span>
                      {/* The name follows the id here while its own column is gone. */}
                      {row.label && <span className="mt-0.5 block truncate text-[11px] text-gray-500 sm:hidden">{row.label}</span>}
                      {row.unregistered && (
                        <span className="mt-0.5 block text-[10px] font-medium text-amber-700">not in the catalog</span>
                      )}
                    </td>
                    <td className="hidden px-2 py-1.5 sm:table-cell">
                      <span className="block truncate text-xs text-gray-600" title={row.label}>{row.label ?? '—'}</span>
                    </td>
                    <td className="hidden px-2 py-1.5 lg:table-cell">
                      <span className="block truncate text-xs text-gray-500" title={row.group}>{row.group ?? '—'}</span>
                    </td>
                    {columns?.detail && (
                      <td className="hidden px-2 py-1.5 xl:table-cell">
                        <span className="block truncate font-mono text-[11px] text-gray-500" title={row.detail}>{row.detail ?? '—'}</span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>

            {total === 0 && (
              <p className="px-3 py-4 text-xs text-gray-400">
                {loading
                  ? `Reading the ${noun.toLowerCase()}s…`
                  : rows.length === 0
                    ? emptyCatalog ?? `No ${noun.toLowerCase()} is registered in this realm yet.`
                    : 'Nothing matches that search and filter.'}
              </p>
            )}
          </div>

          {total > limit && (
            <Pagination
              page={page}
              totalPages={Math.max(1, Math.ceil(total / limit))}
              total={total}
              limit={limit}
              noun={`${noun.toLowerCase()}s`}
              onPageChange={setPage}
              onLimitChange={(next) => { setLimit(next); setPage(1); }}
            />
          )}

          <details className="text-[11px] text-gray-400">
            <summary className="cursor-pointer hover:text-[#001E2B]">Edit the stored list directly</summary>
            <input
              value={ids}
              onChange={(event) => onIdsChange(event.target.value)}
              readOnly={disabled}
              aria-label={`${noun} ids, comma separated`}
              placeholder="comma separated"
              className={`${INPUT} mt-1.5 font-mono text-xs`}
            />
            <p className="mt-1">
              What actually gets stored. For a value this realm has not registered yet, which the
              table above cannot offer.
            </p>
          </details>
        </div>
      )}
    </section>
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
