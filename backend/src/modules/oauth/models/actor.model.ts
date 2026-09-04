/**
 * Who is acting, when that is not simply the subject.
 *
 * RFC 8693's `act` claim. A delegated token names the subject it acts FOR in `sub` and the party
 * doing the acting here, which is what makes "an agent did this on behalf of a person" a fact the
 * trail records rather than something a reader has to infer from two events.
 *
 * Its own file since v40 P6: it used to live beside the stored token record, and that record is
 * gone. Nothing redeemable is kept at rest, but the actor chain is a property of a token's CLAIMS
 * and outlives the collection that once held a copy of them.
 */
export interface ActorClaim {
  /**
   * RFC 8693 4.1 member names, `sub` and `client_id`, not `subjectId` and `clientId`.
   *
   * They were the camelCase forms until v41 P1, which meant a conforming verifier could not read
   * the delegation chain at all: the acting party was invisible to exactly the audience the claim
   * exists for.
   */
  sub: string;
  client_id?: string;
  /** Nested, so a chain of delegation is visible rather than flattened to its last link. */
  act?: ActorClaim;
}

/**
 * How many links the chain has.
 *
 * Bounded by the caller, because an unbounded delegation chain is both a token that grows without
 * limit and an authority nobody can trace to its origin.
 */
export function actorChainDepth(actor?: ActorClaim): number {
  let depth = 0;
  let current = actor;
  while (current) {
    depth += 1;
    current = current.act;
  }
  return depth;
}
