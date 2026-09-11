'use client';
import { Plus, Trash2 } from 'lucide-react';

/**
 * One address per row: add, edit or remove without ever touching a line other than the one meant.
 *
 * Replaces a textarea of newline-separated addresses. A textarea reads back as one big string a
 * person has to parse to find the one entry they meant to change, and it accepts a stray blank line
 * or a pasted comma exactly the way `linesToUris` had to work around. A row is the address itself,
 * so add, edit and remove are three unambiguous actions instead of one text edit with no seams.
 */
export function UriListEditor({
  values,
  onChange,
  placeholder,
  problemFor,
}: {
  values: string[];
  onChange: (values: string[]) => void;
  placeholder: string;
  /** Checked per row, live, so a bad address is flagged where it was typed rather than after Save. */
  problemFor?: (value: string) => string | null;
}) {
  return (
    <div className="space-y-1.5">
      {values.map((value, index) => {
        const problem = value.trim() ? problemFor?.(value) ?? null : null;
        return (
          <div key={index}>
            <div className="flex items-center gap-2">
              <input
                value={value}
                onChange={(event) => onChange(values.map((v, i) => (i === index ? event.target.value : v)))}
                placeholder={placeholder}
                className={`flex-1 rounded-lg border px-2.5 py-2 font-mono text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10 ${
                  problem ? 'border-red-300' : 'border-gray-200 focus:border-[#001E2B]'
                }`}
              />
              <button
                type="button"
                onClick={() => onChange(values.filter((_, i) => i !== index))}
                aria-label="Remove this address"
                className="shrink-0 rounded-md p-1.5 text-gray-400 transition-colors hover:bg-red-50 hover:text-red-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
              >
                <Trash2 size={14} aria-hidden />
              </button>
            </div>
            {problem && <p className="mt-1 text-xs text-red-600">{problem}</p>}
          </div>
        );
      })}
      <button
        type="button"
        onClick={() => onChange([...values, ''])}
        className="flex items-center gap-1 text-xs font-medium text-[#001E2B] hover:underline"
      >
        <Plus size={12} aria-hidden /> Add address
      </button>
      {values.length === 0 && <p className="text-xs text-gray-400">None registered.</p>}
    </div>
  );
}
