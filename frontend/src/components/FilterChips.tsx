'use client';

/** The pill filter row the console sections share, so a filter looks the same wherever it appears. */
export function FilterChips<T extends string>({ label, options, value, onChange }: {
  label: string;
  options: Array<{ key: T; label: string }>;
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.key}
          type="button"
          onClick={() => onChange(option.key)}
          aria-pressed={value === option.key}
          className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
            value === option.key
              ? 'border-[#001E2B] bg-[#001E2B] text-[#00ED64]'
              : 'border-gray-200 bg-white text-gray-600 hover:border-gray-400'
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
