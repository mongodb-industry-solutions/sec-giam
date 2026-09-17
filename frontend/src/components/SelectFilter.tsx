'use client';

/**
 * A filter with too many options to be pills.
 *
 * `FilterChips` is the console's filter, and stays so for a handful of fixed choices. A list whose
 * options come from data (the applications registered in a realm, say) cannot use it: the row would
 * grow with the deployment. Same placement, same border and focus treatment, so the two read as one
 * control family rather than as two designs.
 */
export function SelectFilter({ label, value, onChange, options, anyLabel }: {
  label: string;
  value: string;
  onChange: (next: string) => void;
  options: Array<{ key: string; label: string }>;
  /** What the unfiltered choice is called, e.g. "Any application". */
  anyLabel: string;
}) {
  return (
    <label className="flex items-center gap-2">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        aria-label={label}
        className="rounded-lg border border-gray-200 bg-white px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:border-gray-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <option value="">{anyLabel}</option>
        {options.map((option) => (
          <option key={option.key} value={option.key}>{option.label}</option>
        ))}
      </select>
    </label>
  );
}
