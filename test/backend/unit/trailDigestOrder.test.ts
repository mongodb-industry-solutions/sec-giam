// The audit digest describes what a window HOLDS, not the order one read returned it in.
//
// `find().sort({ ts: 1 })` is not a total order: a busy authority records many events in the same
// millisecond, and two reads of one window return those in different orders. The digest then
// differed while the count did not, so the integrity check reported alteration where nothing had
// been altered. A control that cries wolf is a control that gets switched off, which is exactly what
// TrailDigestService is written to avoid.
import { describe, it, expect } from 'vitest';
import type { Db } from 'mongodb';
import { TrailDigestService } from '../../../backend/src/modules/audit/services/trailDigest.service';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';

const SAME_MILLISECOND = new Date('2026-09-18T10:00:00.000Z');

/** Three events recorded in one millisecond, which is what makes the read order arbitrary. */
const events = [
  { ts: SAME_MILLISECOND, action: 'login', outcome: 'success', correlationId: 'a', meta: { subjectId: 's1' } },
  { ts: SAME_MILLISECOND, action: 'token.issued', outcome: 'success', correlationId: 'b', meta: { subjectId: 's2' } },
  { ts: SAME_MILLISECOND, action: 'session.ended', outcome: 'success', correlationId: 'c', meta: { subjectId: 's3' } },
];

function databaseReturning(order: typeof events): Db {
  return {
    collection: () => ({
      find: () => ({ toArray: async () => order }),
    }),
  } as unknown as Db;
}

/** Signing is not what is under test: a fixed signature keeps the digest the only variable. */
const ring = {
  signingKid: async () => 'kid-1',
  sign: async () => ({ signature: Buffer.from('signature') }),
} as unknown as KeyRing;

const from = new Date('2026-09-18T09:00:00.000Z');
const to = new Date('2026-09-18T11:00:00.000Z');

describe('the audit digest does not depend on the order a window was read in', () => {
  it('seals two different read orders to the same digest', async () => {
    const forward = await new TrailDigestService(databaseReturning(events), ring)
      .seal('r1', from, to, 'urn:test');
    const reversed = await new TrailDigestService(databaseReturning([...events].reverse()), ring)
      .seal('r1', from, to, 'urn:test');

    expect(reversed.digest).toBe(forward.digest);
    expect(reversed.events).toBe(forward.events);
  });

  it('confirms a sealed window read back in another order', async () => {
    const sealed = await new TrailDigestService(databaseReturning(events), ring)
      .seal('r1', from, to, 'urn:test');
    const verdict = await new TrailDigestService(databaseReturning([events[2], events[0], events[1]]), ring)
      .verify('r1', { from: sealed.from, to: sealed.to, digest: sealed.digest, events: sealed.events });

    expect(verdict.intact).toBe(true);
  });

  // The half that matters: reordering is not an alteration, but a changed event is.
  it('still reports an altered event', async () => {
    const sealed = await new TrailDigestService(databaseReturning(events), ring)
      .seal('r1', from, to, 'urn:test');
    const altered = [{ ...events[0], outcome: 'failure' }, events[1], events[2]];
    const verdict = await new TrailDigestService(databaseReturning(altered), ring)
      .verify('r1', { from: sealed.from, to: sealed.to, digest: sealed.digest, events: sealed.events });

    expect(verdict.intact).toBe(false);
  });
});
