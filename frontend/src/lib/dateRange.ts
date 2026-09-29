/**
 * A day range picked in the browser, as the instants an API filters on.
 *
 * Days are the reader's local days: "from" starts at local midnight and "to" ends at the last
 * millisecond of its day, so the same date in both boxes means that one whole day.
 */
export interface DateRange { from: string; to: string }

export const EMPTY_RANGE: DateRange = { from: '', to: '' };

export function rangeBounds(range: DateRange): { from?: string; to?: string } {
  return {
    ...(range.from ? { from: new Date(`${range.from}T00:00:00`).toISOString() } : {}),
    ...(range.to ? { to: new Date(`${range.to}T23:59:59.999`).toISOString() } : {}),
  };
}

/** Whether an ISO timestamp falls inside the range, for lists filtered in the browser. */
export function inRange(ts: string, range: DateRange): boolean {
  const { from, to } = rangeBounds(range);
  return (!from || ts >= from) && (!to || ts <= to);
}
