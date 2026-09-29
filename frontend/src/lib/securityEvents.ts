import { callApi } from './console';

const BATCH = 500;

/**
 * Every event matching a /security-events query, not one page of it.
 *
 * Read in batches with `to` pinned to the first request, because the trail is written continuously
 * and an open window would shift offsets between batches (see the controller's `offset` doc).
 */
export async function readAllSecurityEvents<T>(
  query: Record<string, string | number | undefined>,
  subject: string,
): Promise<T[]> {
  const pinned = { ...query, to: query.to ?? new Date().toISOString() };
  const all: T[] = [];
  for (;;) {
    const body = await callApi<{ events: T[]; total?: number }>('/security-events', {
      query: { ...pinned, offset: all.length, limit: BATCH },
      subject,
    });
    const batch = body.events ?? [];
    all.push(...batch);
    if (batch.length < BATCH || all.length >= (body.total ?? 0)) return all;
  }
}
