import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * The platform session, as a record rather than an implication.
 *
 * It used to be a signed cookie and a counter, which means nobody could list it, end it from
 * elsewhere, or count how many a principal had. Making it a record is what turns single logout,
 * concurrent-session limits and "sign this person out everywhere" from claims into operations.
 */
export interface SessionRecord extends Scoped {
  sessionId: string;
  subjectId: string;
  /** Incremented to invalidate every token issued before it, without listing them. */
  epoch: number;

  createdAt: string;
  lastSeenAt: string;
  /** Absolute end, regardless of activity. */
  expiresAt: string;
  /** Rolling end, moved forward on use. */
  idleExpiresAt: string;

  /** Every client that holds a live token for this session, so logout can notify each of them. */
  clientIds: string[];

  /** Hashed, never raw: a session record is not a place to accumulate personal data. */
  userAgentHash?: string;
  ipHash?: string;

  terminatedAt?: string;
  terminationReason?: 'logout' | 'expired' | 'revoked' | 'superseded';
  meta: Meta;
}

export function isLive(session: Pick<SessionRecord, 'terminatedAt' | 'expiresAt' | 'idleExpiresAt'>, now = new Date()): boolean {
  if (session.terminatedAt) return false;
  const at = now.getTime();
  return Date.parse(session.expiresAt) > at && Date.parse(session.idleExpiresAt) > at;
}
