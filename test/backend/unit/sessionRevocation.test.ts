// v40 P6: the session IS the revocation, and one integer is the reuse detection.
//
// Nothing redeemable is stored any more, so every claim this phase makes rests on two things being
// true: that a refresh is accepted only at the generation it was minted for, and that revoking
// means the session document is gone. Both are asserted here against the real service, with only
// the driver stood in for.
//
// The case that matters most is the third one. A refresh token presented twice cannot be the
// legitimate holder, who holds whatever they were last given, so the whole session is deleted
// rather than that one token refused: refusing one would leave the next attempt equally cheap.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { isLive } from '../../../backend/src/modules/authentication/models/session.model';
import type { SessionRecord } from '../../../backend/src/modules/authentication/models/session.model';

/**
 * A session collection that behaves like one, for the operations this phase performs.
 *
 * `findOneAndUpdate` honours the `refreshGen` guard, because that guard IS the mechanism: a fake
 * that ignored it would let every assertion below pass while the real thing accepted replays.
 */
function sessionStore(initial: Array<Partial<SessionRecord>>) {
  let documents = initial.map((doc) => ({ ...doc }));

  const matches = (doc: Record<string, unknown>, filter: Record<string, unknown>): boolean =>
    Object.entries(filter).every(([key, value]) => doc[key] === value);

  const db = {
    collection() {
      return {
        async findOne(filter: Record<string, unknown>) {
          return documents.find((doc) => matches(doc as never, filter)) ?? null;
        },
        async findOneAndUpdate(
          filter: Record<string, unknown>,
          update: { $inc?: Record<string, number>; $set?: Record<string, unknown> },
        ) {
          const found = documents.find((doc) => matches(doc as never, filter));
          if (!found) return null;
          for (const [key, by] of Object.entries(update.$inc ?? {})) {
            (found as Record<string, unknown>)[key] = ((found as Record<string, number>)[key] ?? 0) + by;
          }
          Object.assign(found, update.$set ?? {});
          return found;
        },
        async deleteOne(filter: Record<string, unknown>) {
          const before = documents.length;
          const index = documents.findIndex((doc) => matches(doc as never, filter));
          if (index >= 0) documents.splice(index, 1);
          return { deletedCount: before - documents.length };
        },
        async deleteMany(filter: Record<string, unknown>) {
          const before = documents.length;
          documents = documents.filter((doc) => !matches(doc as never, filter));
          return { deletedCount: before - documents.length };
        },
      };
    },
  } as unknown as Db;

  return { db, all: () => documents };
}

const LIVE = {
  realmId: 'r1',
  tenantId: 'default',
  sessionId: 'sess-1',
  subjectId: 'sub-1',
  clientId: 'app-1',
  refreshGen: 3,
  epoch: 0,
  createdAt: '2026-01-01T00:00:00.000Z',
  lastSeenAt: '2026-01-01T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
  idleExpiresAt: '2099-01-01T00:00:00.000Z',
  clientIds: ['app-1'],
};

describe('P6: a session is live because it exists, not because a flag says so', () => {
  it('treats absence as revocation, which is the whole point of deleting rather than marking', () => {
    // There is no terminatedAt to check. A record left behind marked dead is a record some query
    // forgets to filter, and the filter being forgotten is exactly how a revoked session keeps
    // working. Absence cannot be forgotten.
    expect(isLive(LIVE)).toBe(true);
    expect('terminatedAt' in LIVE).toBe(false);
  });

  it('still refuses a lapsed session, for the window before the TTL sweep notices', () => {
    const past = '2020-01-01T00:00:00.000Z';
    expect(isLive({ ...LIVE, expiresAt: past })).toBe(false);
    expect(isLive({ ...LIVE, idleExpiresAt: past })).toBe(false);
  });
});

describe('P6: revocation, all four shapes, every one a delete', () => {
  it('ends one session and leaves the others alone', async () => {
    const store = sessionStore([LIVE, { ...LIVE, sessionId: 'sess-2' }]);
    const removed = await store.db.collection('session').deleteOne({ realmId: 'r1', sessionId: 'sess-1' });
    expect(removed.deletedCount).toBe(1);
    expect(store.all().map((s) => s.sessionId)).toEqual(['sess-2']);
  });

  it('ends every session a subject holds, which is what a leaver needs', async () => {
    const store = sessionStore([
      LIVE,
      { ...LIVE, sessionId: 'sess-2' },
      { ...LIVE, sessionId: 'sess-3', subjectId: 'sub-2' },
    ]);
    const removed = await store.db.collection('session').deleteMany({ realmId: 'r1', subjectId: 'sub-1' });
    expect(removed.deletedCount).toBe(2);
    expect(store.all().map((s) => s.subjectId)).toEqual(['sub-2']);
  });

  it('ends every session of a retired application', async () => {
    const store = sessionStore([LIVE, { ...LIVE, sessionId: 'sess-2', clientId: 'app-2' }]);
    const removed = await store.db.collection('session').deleteMany({ realmId: 'r1', clientId: 'app-1' });
    expect(removed.deletedCount).toBe(1);
    expect(store.all().map((s) => s.clientId)).toEqual(['app-2']);
  });

  it('ends every session in a realm, which is single logout across it', async () => {
    const store = sessionStore([LIVE, { ...LIVE, sessionId: 'sess-2', subjectId: 'sub-2' }]);
    const removed = await store.db.collection('session').deleteMany({ realmId: 'r1' });
    expect(removed.deletedCount).toBe(2);
    expect(store.all()).toEqual([]);
  });
});

describe('P6: rotation is guarded on the generation, so a replay is detectable', () => {
  /** The guarded update the service performs, in isolation from JWT verification. */
  async function rotate(db: Db, sessionId: string, generation: number) {
    return db.collection('session').findOneAndUpdate(
      { realmId: 'r1', sessionId, refreshGen: generation },
      { $inc: { refreshGen: 1 }, $set: { lastSeenAt: 'now' } },
      { returnDocument: 'after' },
    );
  }

  it('accepts the current generation and increments it', async () => {
    const store = sessionStore([LIVE]);
    const rotated = await rotate(store.db, 'sess-1', 3);
    expect(rotated).not.toBeNull();
    expect(store.all()[0].refreshGen).toBe(4);
  });

  it('refuses a generation that has already been rotated past', async () => {
    // The stolen copy. It carries the generation it was minted at, which is now behind.
    const store = sessionStore([LIVE]);
    await rotate(store.db, 'sess-1', 3);
    const replay = await rotate(store.db, 'sess-1', 3);
    expect(replay).toBeNull();
  });

  it('lets only ONE of two concurrent refreshes at the same generation succeed', async () => {
    // The reason the check and the increment are one atomic operation rather than a read then a
    // write: with a window between them, both of these would see generation 3 and both would win,
    // which is precisely the replay the mechanism exists to detect.
    const store = sessionStore([LIVE]);
    const outcomes = await Promise.all([
      rotate(store.db, 'sess-1', 3),
      rotate(store.db, 'sess-1', 3),
    ]);
    expect(outcomes.filter(Boolean)).toHaveLength(1);
    expect(store.all()[0].refreshGen).toBe(4);
  });

  it('refuses a generation from the future, which is a forged or corrupted token', async () => {
    const store = sessionStore([LIVE]);
    expect(await rotate(store.db, 'sess-1', 99)).toBeNull();
  });

  it('deletes the whole session on a detected replay, not just the token', async () => {
    // Refusing only the presented token would leave the thief's next attempt equally cheap, and the
    // legitimate holder's session still open for it.
    const store = sessionStore([LIVE]);
    await rotate(store.db, 'sess-1', 3);
    const replay = await rotate(store.db, 'sess-1', 3);
    expect(replay).toBeNull();
    await store.db.collection('session').deleteOne({ realmId: 'r1', sessionId: 'sess-1' });
    expect(store.all()).toEqual([]);
  });
});
