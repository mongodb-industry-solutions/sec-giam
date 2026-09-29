/**
 * The one place the HTTP address scheme is decided.
 *
 * Everything this service answers sits under `API_PREFIX`, protocol surfaces included: a realm's
 * issuer is `${base}${API_PREFIX}/realms/:realm`, so its OpenID Connect endpoints, discovery and
 * federation callbacks live beside its API. The issuer is part of every token, so a future `/api/v2`
 * adds routes without moving the issuer. Only RFC 8414's root form
 * (`/.well-known/oauth-authorization-server/...`) and `/health` sit outside it.
 */
export const API_PREFIX = '/api/v1';

/** Where a realm's administrative and API routes live, for building links and `Location` values. */
export function realmApiPath(realm: string): string {
  return `${API_PREFIX}/realms/${realm}`;
}
