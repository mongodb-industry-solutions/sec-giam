import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A pending authorization awaiting a user action.
 *
 * An authorization code and a backchannel request are the same thing seen from two directions, so
 * they are one collection discriminated by `flow`, with one TTL index instead of two. The states,
 * the expiry and the replay rules are then written once and cannot drift between them.
 */

export type AuthorizationFlow = 'authorization_code' | 'ciba';

export type AuthorizationStatus = 'pending' | 'approved' | 'denied' | 'consumed' | 'expired';

export interface AuthorizationRequestRecord extends Scoped {
  requestId: string;
  flow: AuthorizationFlow;
  clientId: string;
  subjectId?: string;
  status: AuthorizationStatus;

  /**
   * The code, hashed.
   *
   * Stored as a digest for the same reason a password is: whoever reads this collection must not come
   * away able to redeem an outstanding authorization.
   */
  codeHash?: string;
  pkce?: {
    challenge: string;
    method: 'S256' | 'plain';
  };
  redirectUri?: string;
  state?: string;
  /** The correlator an audit trail groups a whole flow by, without storing the state itself. */
  stateHash?: string;
  nonce?: string;
  scope: string;

  /** Backchannel flow: the identifiers and the message the user is shown on their device. */
  authReqId?: string;
  challenge?: string;
  bindingMessage?: string;
  loginHint?: string;
  clientNotificationToken?: string;
  interval?: number;

  attemptCount: number;
  expiresAt: string;
  meta: Meta;
}

/**
 * Consumed rather than deleted.
 *
 * A replayed code has to be DETECTED, not merely absent: deleting on use makes a replay
 * indistinguishable from a code that never existed, and those are very different events. One is a
 * typo and the other is an attack in progress.
 */
export function isRedeemable(
  request: Pick<AuthorizationRequestRecord, 'status' | 'expiresAt'>,
  now = new Date(),
): boolean {
  return request.status === 'approved' || request.status === 'pending'
    ? Date.parse(request.expiresAt) > now.getTime()
    : false;
}
