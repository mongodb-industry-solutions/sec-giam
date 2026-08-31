import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A principal consenting to a client's scopes.
 *
 * This is the OAuth half of a word that names two different things. The other half, consent to access
 * an account under payment-services regulation, is regulated business data that belongs to the
 * institution holding the account and is never modelled here. The authority has no business knowing
 * an account exists, so it cannot represent a consent to reach one even if asked.
 */
export interface GrantRecord extends Scoped {
  grantId: string;
  subjectId: string;
  clientId: string;
  /** Space-delimited, matching the token request that will be judged against it. */
  scope: string;
  status: 'active' | 'revoked';
  grantedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
  meta: Meta;
}

export function grantedScopes(grant: Pick<GrantRecord, 'scope'>): string[] {
  return grant.scope.split(' ').filter(Boolean);
}

/** Whether a grant still covers everything a request asks for. A partial grant is not a grant. */
export function covers(grant: Pick<GrantRecord, 'scope' | 'status'>, requested: string[]): boolean {
  if (grant.status !== 'active') return false;
  const held = new Set(grantedScopes(grant));
  return requested.every((scope) => held.has(scope));
}
