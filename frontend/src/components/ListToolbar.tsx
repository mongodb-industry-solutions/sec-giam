'use client';

import type { ReactNode } from 'react';
import { SearchInput } from './SearchInput';
import { FilterChips } from './FilterChips';

/**
 * The row above every list: search on the left, filter pills on the right.
 *
 * Kept as one component so a section cannot have a search without a filter row wired the same way as
 * its neighbours, or reinvent the chip markup by hand. A section with only one of the two simply
 * omits the corresponding prop; the layout still lines up.
 */
export function ListToolbar<T extends string>({ search, filter, extra }: {
  search?: { value: string; onChange: (next: string) => void; placeholder?: string; label?: string };
  filter?: { label: string; options: Array<{ key: T; label: string }>; value: T; onChange: (next: T) => void };
  extra?: ReactNode;
}) {
  if (!search && !filter && !extra) return null;
  return (
    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      {search && <div className="sm:max-w-sm sm:flex-1"><SearchInput {...search} /></div>}
      <div className="flex flex-wrap items-center gap-2">
        {filter && <FilterChips {...filter} />}
        {extra}
      </div>
    </div>
  );
}
