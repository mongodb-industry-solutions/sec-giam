'use client';

import { Tooltip } from '../../../components/Tooltip';
import type { PolicyCondition } from './types';

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

export function DisabledBadge() {
  return (
    <Tooltip text="Switched off. It is still stored and still editable, and it decides nothing while it stays this way.">
      <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
        disabled
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
  return parts;
}
