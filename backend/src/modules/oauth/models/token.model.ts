import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * An issued token, recorded so it can be revoked and so a replay can be detected.
 *
 * The record is not what a resource server verifies against: verification is a signature check
 * against the published key set, with no call here. What this collection buys is the ability to
 * answer "is this still valid" when the answer has to be authoritative, and to say what was issued
 * when someone asks afterwards.
 */

export type TokenType = 'access' | 'refresh' | 'id';

/** RFC 8693 delegation: who is acting, for whom, appended one hop at a time. */
export interface ActorClaim {
  subjectId: string;
  clientId?: string;
  /** The next hop out, so the chain reads from the current actor back to the origin. */
  actor?: ActorClaim;
}

export interface TokenRecord extends Scoped {
  tokenId: string;
  jti: string;
  type: TokenType;
  subjectId?: string;
  clientId: string;
  scope: string;
  sessionId?: string;

  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
  revocationReason?: string;

  /** Present when the token was obtained by exchange rather than issued to its subject directly. */
  actor?: ActorClaim;

  meta: Meta;
}

export function isRevoked(token: Pick<TokenRecord, 'revokedAt'>): boolean {
  return Boolean(token.revokedAt);
}

/** Depth of the delegation chain, which a realm bounds so a token cannot be exchanged indefinitely. */
export function actorChainDepth(actor?: ActorClaim): number {
  let depth = 0;
  for (let hop = actor; hop; hop = hop.actor) depth += 1;
  return depth;
}
