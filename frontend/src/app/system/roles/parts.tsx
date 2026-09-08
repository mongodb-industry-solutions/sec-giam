'use client';

import type { ReactNode } from 'react';
import { Tooltip } from '../../../components/Tooltip';

/** The small pieces both role screens use. Kept out of the pages so neither owns the other's shape. */

export const INPUT =
  'mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10';

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-gray-600">{label}</span>
      {children}
      {hint && <span className="mt-0.5 block text-[11px] text-gray-400">{hint}</span>}
    </label>
  );
}

/**
 * The tier, on the role that decides it.
 *
 * Realm wide is what makes a role administrative, and it is a property of the role rather than of
 * each permission because the answer is the same for all of them.
 */
export function ScopeBadge({ scopeKind }: { scopeKind: 'self' | 'all' }) {
  return (
    <Tooltip text={scopeKind === 'all'
      ? 'Reaches records across the realm, not only the holder\'s own. This is what makes a role administrative.'
      : 'Reaches only the holder\'s own records, whatever the permissions say.'}>
      <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${
        scopeKind === 'all' ? 'border-amber-200 bg-amber-50 text-amber-700' : 'border-gray-200 bg-gray-50 text-gray-600'
      }`}>
        {scopeKind === 'all' ? 'realm wide' : 'own records'}
      </span>
    </Tooltip>
  );
}

export function BuiltinBadge() {
  return (
    <Tooltip text="Ships with the deployment. Setup recreates the fields it owns, so removing it here would not remove it.">
      <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600">
        built in
      </span>
    </Tooltip>
  );
}

/** Shown only when a role is switched off: grants nothing, everywhere it is held or inherited from. */
export function DisabledBadge() {
  return (
    <Tooltip text="Switched off. Every assignment survives untouched, and grants nothing while it stays this way, including to anything that inherits from it.">
      <span className="rounded border border-red-200 bg-red-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-red-700">
        disabled
      </span>
    </Tooltip>
  );
}
