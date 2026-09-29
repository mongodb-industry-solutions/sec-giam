import { useEffect, useMemo, useState } from 'react';

/**
 * Search, filter and paging over a list the page already holds in full.
 *
 * For bounded reads (a grant's trail, say) where a round trip per keystroke buys nothing. Lists the
 * authority pages itself keep their filters on the server; this is not a substitute for that.
 */
export function useLocalList<T, F extends string>(items: T[], options: {
  matches: (item: T, needle: string) => boolean;
  filterBy?: (item: T, filter: F) => boolean;
  initialFilter: F;
  initialLimit?: number;
}) {
  const { matches, filterBy, initialFilter, initialLimit = 20 } = options;
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<F>(initialFilter);
  const [page, setPage] = useState(1);
  const [limit, setLimit] = useState(initialLimit);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items.filter((item) => (!needle || matches(item, needle)) && (!filterBy || filterBy(item, filter)));
  }, [items, search, filter, matches, filterBy]);

  // A new search starts on the first page.
  useEffect(() => { setPage(1); }, [search, filter, items]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / limit));
  const visible = filtered.slice((page - 1) * limit, page * limit);

  return {
    search, setSearch, filter, setFilter, filtered, visible,
    pagination: {
      page, totalPages, total: filtered.length, limit,
      onPageChange: setPage,
      onLimitChange: (next: number) => { setLimit(next); setPage(1); },
    },
  };
}
