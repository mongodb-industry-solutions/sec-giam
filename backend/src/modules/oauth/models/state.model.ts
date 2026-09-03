import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A pending authorization awaiting a user action.
 *
 * An authorization code and a backchannel request are the same thing seen from two directions, so
 * they are one collection discriminated by `flow`, with one TTL index instead of two. The states,
 * the expiry and the replay rules are then written once and cannot drift between them.
 */

/**
 * Which flow this pending authorization belongs to.
 *
 * `par` is RESERVED and not yet implemented (P7.4). Pushed Authorization Requests are a third way of
 * starting the same thing, so when they arrive they are a third value here rather than a new
 * collection with its own TTL, its own indexes and its own expiry bug.
 */
export type AuthorizationFlow = 'authorization_code' | 'ciba' | 'par';

export type AuthorizationStatus = 'pending' | 'approved' | 'denied' | 'consumed' | 'expired';

export interface StateRecord extends Scoped {
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

  /**
   * Which authentication domain is being used.
   *
   * Follows from the domain model: a realm may offer several ways in, and which one an attempt used
   * is part of what happened rather than something to infer from the credential afterwards.
   */
  domainId?: string;

  /**
   * Which resources access is requested for. RFC 8707 resource indicators.
   *
   * Recorded on the request because the audience of the eventual token is decided here, at the point
   * the client asked, and not re-derived later from whatever happens to be registered.
   */
  resources?: string[];

  /** Which credential was presented. Known only after an attempt, so optional by nature. */
  credentialId?: string;

  /**
   * The session created on success.
   *
   * Closes the trail from "somebody pressed sign in" to "this session is live". Without it there is
   * a gap exactly where an investigation needs to cross from an attempt to its consequence.
   */
  sessionId?: string;

  /** Why the attempt ended as it did, while the flow is alive. A CIBA client polls and must be told. */
  cause?: string;

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
/**
 * Why redemption marks `consumed` instead of deleting the record.
 *
 * P7.3. A replayed code has to be DETECTED, not merely absent. Deleting on use makes a replay and a
 * fabricated code indistinguishable, and one of those is a typo while the other is an attack in
 * progress. The record then expires on its own TTL, in minutes, so the detection window costs
 * nothing durable.
 *
 * This is the one place in the model where state must be written at all: an authorization code is a
 * claim ticket handed over in one channel and redeemed in another, seconds later, possibly on a
 * different instance, and the PKCE challenge has to be remembered in order to be compared.
 */
export function isRedeemable(
  request: Pick<StateRecord, 'status' | 'expiresAt'>,
  now = new Date(),
): boolean {
  return request.status === 'approved' || request.status === 'pending'
    ? Date.parse(request.expiresAt) > now.getTime()
    : false;
}
