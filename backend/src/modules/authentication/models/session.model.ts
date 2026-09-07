import { Meta, Scoped } from '../../../shared/models/base.model';
import { AuthenticationContext } from './authenticationContext';

/**
 * The fact that access is still live.
 *
 * NO TOKEN IS STORED, and that is the point of this record rather than an omission from it. An
 * access token and a refresh token are both JWTs: storing one keeps a redeemable artifact at rest,
 * and storing a row per issued token put the highest write rate in the system on data carrying
 * nothing the token did not already carry.
 *
 * What is worth storing is that a session exists, because the ABSENCE of this document is the
 * revocation signal. That is stronger and simpler than a `notBefore` timestamp: nothing has to be
 * compared, and no entry has to be kept alive until the last affected token expires.
 *
 * Accepted limit, stated rather than hidden: an access token already issued stays valid until it
 * expires, because it is verified without touching the database, which is the whole reason it
 * scales. With a five minute lifetime that window is the maximum exposure and it is the stated
 * revocation objective.
 */
export interface SessionRecord extends Scoped, AuthenticationContext {
  sessionId: string;
  subjectId: string;
  /** The client the session was established for. Logout by client is a delete on this. */
  clientId?: string;

  /**
   * The authentication path that established this session.
   *
   * Carried because the concurrent-session limit belongs to the domain that authenticated it: a
   * realm with two domains applies each domain's limit to its own sessions.
   */
  domainId?: string;

  /**
   * The pending authorization this session came from.
   *
   * Closes the trail from "somebody pressed sign in" to "this session is live", which otherwise
   * has a gap exactly where an investigation needs to cross it.
   *
   * NOT the source of the `txn` claim, though it looks like it should be: one session produces many
   * flows, so this names whichever was most recent. The flow travels in the refresh token instead.
   */
  ticketId?: string;

  /**
   * The refresh generation, and the whole of reuse detection.
   *
   * RFC 9700 requires rotation with reuse detection, and detection requires remembering something.
   * That something is one integer. The refresh JWT carries `sid` and `gen`; a refresh is accepted
   * only when `gen` equals this, and this is then incremented. A stolen refresh replayed after the
   * legitimate one rotated arrives with a LOWER generation, does not match, and the whole session
   * is deleted on the assumption of theft.
   *
   * Incremented per refresh, per session, so it is not a hot document: nothing is written per
   * issued token.
   */
  refreshGen: number;

  /** Incremented to invalidate every token issued before it, without listing them. */
  epoch: number;

  /**
   * When the authentication happened, and therefore the source of the OIDC `auth_time`.
   *
   * No separate `authTime` field: a session is created by one sign-in, so the two would always hold
   * the same value and one of them would eventually be updated without the other.
   */
  createdAt: string;
  lastSeenAt: string;
  /** Absolute end, regardless of activity. The TTL index expires the document on it. */
  expiresAt: string;
  /** Rolling end, moved forward on use. */
  idleExpiresAt: string;

  /** Every client that holds a live token for this session, so logout can notify each of them. */
  clientIds: string[];

  /** Hashed, never raw: a session record is not a place to accumulate personal data. */
  userAgentHash?: string;
  ipHash?: string;
  meta: Meta;
}

/**
 * Whether a session is live.
 *
 * There is no `terminatedAt` any more. A terminated session is a DELETED session, because a record
 * that lingers marked dead is a record some query will forget to filter, and the filter being
 * forgotten is how a revoked session keeps working. Absence cannot be forgotten.
 *
 * The expiry checks remain, for the window between a session lapsing and the TTL sweep noticing.
 */
export function isLive(session: Pick<SessionRecord, 'expiresAt' | 'idleExpiresAt'>, now = new Date()): boolean {
  const at = now.getTime();
  return Date.parse(session.expiresAt) > at && Date.parse(session.idleExpiresAt) > at;
}

/** The claims a refresh token carries. Nothing else: it is redeemed here and verified nowhere else. */
export interface RefreshClaims {
  sid: string;
  gen: number;
  sub?: string;
  client_id: string;
  /**
   * The flow this rotation chain belongs to, RFC 8417 2.2.
   *
   * Carried IN the token rather than looked up, because a session produces many flows and could not
   * say which one minted this refresh token. This is what keeps every rotation of one chain filed
   * under one flow with no stored state.
   */
  txn?: string;
}
