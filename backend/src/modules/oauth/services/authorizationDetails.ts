import { GrantRecord } from '../../consent/models/grant.model';

/**
 * A grant's constraints, as an RFC 9396 `authorization_details` claim.
 *
 * WHAT THIS IS: the authorization DECISION, transported. Not a policy. A policy is a rule with
 * conditions and an effect, evaluated against a request; this is the already-decided authority with
 * its parameters, enforced by comparison. That distinction is why an amount is a defect in the
 * `policy` collection and legitimate here: one is a rule about many subjects, the other a constraint
 * granted to one token.
 *
 * WHY IT TRAVELS AT ALL: `grant.constraints` existed and reached no resource server, under either
 * verification model. A resource server verifying locally could not see a value ceiling, so a token
 * limited to 500 was indistinguishable from one with no limit. Carrying the constraint means the
 * information was available; whether the resource server reads it is its own decision, and
 * `resource.validationMode` is where it declares which.
 */

/**
 * The type this authority uses when a deployment has registered none.
 *
 * `urn:giam:constrained-grant` and NOT a business name. RFC 9396 2 puts the interpretation of `type`
 * in the authorization server's hands, and in this design that means the deployment's resource
 * catalog. A built-in `payment_initiation` would put one industry's vocabulary inside an authority
 * that has to serve several, which is what `dayOneInvariants.test.ts` exists to prevent.
 */
export const DEFAULT_AUTHORIZATION_DETAIL_TYPE = 'urn:giam:constrained-grant';

export interface AuthorizationDetail {
  type: string;
  /** The actions the grant permits, from its scope. */
  actions?: string[];
  /** Which resources the delegate may reach, where the grant names them. */
  locations?: string[];
  /**
   * A numeric ceiling. A plain number, matching `grant.constraints.maxValue`.
   *
   * NOT an `{ amount, currency }` pair: what the ceiling counts is the deployment's business, and a
   * currency would make this authority know it was money.
   */
  maxValue?: number;
  /** Bound to one task, so a token minted for one cannot be reused for another. */
  transactionId?: string;
  /** How many further hops the authority may be delegated onward. */
  maxDepth?: number;
}

/**
 * Whether a grant carries anything a token needs to say.
 *
 * A grant with no constraints produces no claim, rather than an empty array: a resource server
 * seeing `authorization_details: []` would have to decide whether that means unconstrained or
 * unknown, and those are different.
 */
export function hasConstraints(grant: Pick<GrantRecord, 'constraints'>): boolean {
  const constraints = grant.constraints;
  if (!constraints) return false;
  return constraints.maxValue !== undefined
    || Boolean(constraints.allowedResources?.length)
    || Boolean(constraints.allowedTools?.length);
}

/**
 * Projects a grant into the claim, filtered to one audience.
 *
 * RFC 9396 9.1 recommends adding the object "filtered to the specific audience". With a
 * multi-valued `aud` that matters: a resource server must not receive constraints addressed to
 * another. `allowedResources` is the filter, and when the grant names none the constraint applies
 * wherever the token is accepted.
 */
export function authorizationDetailsFor(
  grant: Pick<GrantRecord, 'constraints' | 'scope' | 'transactionId' | 'maxDepth'>,
  audience: string[],
  type: string = DEFAULT_AUTHORIZATION_DETAIL_TYPE,
): AuthorizationDetail[] {
  const constraints = grant.constraints;
  if (!constraints && grant.transactionId === undefined && grant.maxDepth === undefined) return [];

  const allowed = constraints?.allowedResources ?? [];
  const locations = allowed.length > 0 ? allowed.filter((entry) => audience.includes(entry)) : [];
  // Named resources that none of this token's audiences match: the constraint is not for any
  // resource server reading THIS token, so the detail is not addressed to it.
  if (allowed.length > 0 && locations.length === 0) return [];

  const actions = grant.scope.split(' ').filter(Boolean);
  const detail: AuthorizationDetail = {
    type,
    ...(actions.length ? { actions } : {}),
    ...(locations.length ? { locations } : {}),
    ...(constraints?.maxValue !== undefined ? { maxValue: constraints.maxValue } : {}),
    ...(constraints?.allowedTools?.length ? { locations: [...locations, ...constraints.allowedTools] } : {}),
    ...(grant.transactionId ? { transactionId: grant.transactionId } : {}),
    ...(grant.maxDepth !== undefined ? { maxDepth: grant.maxDepth } : {}),
  };
  return [detail];
}
