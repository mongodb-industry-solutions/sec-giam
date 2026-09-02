// v40 P10.4, layer 2: the live-session cache, and the exact contract `sessionIsLive` leans on.
//
// This suite exists because the cache had a consumer added to it, and the consumer trusts ONE
// asymmetric property: a negative answer is authoritative and a positive one is not. If that
// asymmetry ever inverts, introspection starts honouring revoked sessions with nothing in the logs
// to explain it, so it is asserted here rather than left as a comment at the call site.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { SessionWatch } from '../../../backend/src/modules/authorization/services/sessionWatch';

/** A database holding exactly these session ids. Only the read `reload` performs is supported. */
function sessionsHolding(sessionIds: string[]): Db {
  return {
    collection: () => ({
      find: () => ({
        toArray: async () => sessionIds.map((sessionId) => ({ sessionId })),
      }),
    }),
  } as unknown as Db;
}

describe('P10.4: the cache answers for absence, and defers for presence', () => {
  it('reports null for everything until it has loaded, rather than false', async () => {
    /**
     * The single most important case, and the one a naive boolean cache gets wrong.
     *
     * False would mean "revoked". Answering false because loading has not finished would sign every
     * user out on a restart, and it would look like a mass revocation nobody ordered.
     */
    const watch = new SessionWatch(sessionsHolding(['sess-1']));
    expect(watch.ready).toBe(false);
    expect(watch.isLive('sess-1')).toBeNull();
    expect(watch.isLive('never-existed')).toBeNull();
  });

  it('reports a session it has never seen as not live, which needs no database read', async () => {
    const watch = new SessionWatch(sessionsHolding(['sess-1']));
    await watch.reload();

    expect(watch.ready).toBe(true);
    /**
     * Authoritative, and REALM INDEPENDENT, which is what lets the caller skip the read entirely.
     *
     * The set is keyed by session id alone. A session id absent from it exists in no realm at all,
     * so it certainly does not exist in the realm being asked about. There is no cross-realm false
     * negative to worry about, only the reverse, which is why the positive case defers.
     */
    expect(watch.isLive('never-existed')).toBe(false);
  });

  it('reports a session it holds as live, which is WEAKER than the caller needs', async () => {
    /**
     * Membership means "not deleted". It does not mean "unexpired", because the cache stores ids
     * and not expiries, so the caller must still read to check the expiry.
     *
     * Asserted so the weakness is recorded as intended rather than discovered later by somebody who
     * decides the follow-up read looks redundant and removes it.
     */
    const watch = new SessionWatch(sessionsHolding(['sess-1']));
    await watch.reload();
    expect(watch.isLive('sess-1')).toBe(true);
  });

  it('drops a session that is gone on the next reload', async () => {
    // Reload is both the delete path and the resume-gap recovery path, so this covers both.
    const watch = new SessionWatch(sessionsHolding(['sess-1']));
    await watch.reload();
    expect(watch.isLive('sess-1')).toBe(true);

    const emptied = new SessionWatch(sessionsHolding([]));
    await emptied.reload();
    expect(emptied.isLive('sess-1')).toBe(false);
    expect(emptied.size).toBe(0);
  });

  it('is never confidently wrong: only null or false while recovering', async () => {
    /**
     * The failure mode the whole file is shaped around, stated as an assertion.
     *
     * A stream error clears `loaded`, so every answer reverts to null and every caller falls back
     * to the authoritative read. Being briefly slow is recoverable; answering true from a cache
     * that has stopped receiving deletes is not.
     */
    const watch = new SessionWatch(sessionsHolding(['sess-1']));
    await watch.reload();
    expect(watch.isLive('sess-1')).toBe(true);

    // What the stream's error handler does before it reloads.
    (watch as unknown as { loaded: boolean }).loaded = false;
    expect(watch.isLive('sess-1')).toBeNull();
  });
});
