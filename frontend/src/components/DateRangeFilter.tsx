'use client';

import { X } from 'lucide-react';
import type { DateRange } from '../lib/dateRange';

const inputClass = 'h-9 rounded-lg border border-gray-200 bg-white px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10';

/** From/to day pickers. The same day in both searches that day alone. */
export function DateRangeFilter({ value, onChange }: { value: DateRange; onChange: (next: DateRange) => void }) {
  const today = new Date().toLocaleDateString('en-CA');
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Date range">
      <input
        type="date"
        aria-label="From day"
        value={value.from}
        max={value.to || today}
        onChange={(event) => onChange({ ...value, from: event.target.value })}
        className={inputClass}
      />
      <span className="text-xs text-gray-400">to</span>
      <input
        type="date"
        aria-label="To day"
        value={value.to}
        min={value.from || undefined}
        max={today}
        onChange={(event) => onChange({ ...value, to: event.target.value })}
        className={inputClass}
      />
      <button
        type="button"
        onClick={() => onChange({ from: today, to: today })}
        className="h-9 rounded-lg border border-gray-200 bg-white px-2.5 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        Today
      </button>
      {(value.from || value.to) && (
        <button
          type="button"
          onClick={() => onChange({ from: '', to: '' })}
          aria-label="Clear dates"
          className="flex h-9 w-9 items-center justify-center rounded-lg text-gray-400 transition-colors hover:bg-gray-100 hover:text-gray-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          <X size={13} aria-hidden />
        </button>
      )}
    </div>
  );
}
