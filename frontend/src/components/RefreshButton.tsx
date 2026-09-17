'use client';

import { RefreshCw } from 'lucide-react';
import { Tooltip } from './Tooltip';

/**
 * Re-read a list on demand, for anything whose answer changes without this console doing it.
 *
 * Every screen here reads once and then shows that answer until something on the page causes a
 * write. That is right for a catalog and wrong for live state: sessions open and lapse while
 * somebody is looking at the list, and the only way to see it was to leave and come back.
 *
 * Shared rather than inlined per page so the spinner, the disabled state and the wording stay the
 * same wherever a list offers this.
 */
export function RefreshButton({ onClick, busy = false, label = 'Refresh', hint }: {
  onClick: () => void;
  busy?: boolean;
  label?: string;
  hint?: string;
}) {
  const button = (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      // The label is read out even while the icon spins, so this is never an unnamed button.
      aria-label={busy ? `${label}, in progress` : label}
      className="flex items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
    >
      <RefreshCw size={13} className={busy ? 'animate-spin' : ''} aria-hidden />
      {label}
    </button>
  );

  return hint ? <Tooltip text={hint}>{button}</Tooltip> : button;
}
