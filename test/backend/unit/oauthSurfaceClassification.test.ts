// A thrown error on an "OAuth surface" answers RFC 6749 5.2 ({error, error_description}); everywhere
// else it answers RFC 9457 problem+json. Getting a path wrong is not cosmetic: the route's OWN
// response schema still expects whichever shape ITS spec declares, so a misclassified path sends a
// body that fails to serialize against that schema and turns the original error into a 500.
import { describe, it, expect } from 'vitest';
import { isOAuthSurface } from '../../../backend/src/shared/models/problem';

describe('isOAuthSurface: which paths a thrown error answers as OAuth, not Problem', () => {
  it('excludes /protocol/oidc/logout, which is deliberately Problem+json', () => {
    // THE DEFECT THIS GUARDS AGAINST. logout.controller.ts declares `response.400: {$ref:
    // 'Problem#'}`, but the broad `/protocol/oidc/` prefix caught it anyway: a thrown
    // error on this route sent an OAuthError body (no `type`) into a schema that requires one,
    // and the serializer itself failed with "type is required!", turning the original error into
    // an unrelated 500.
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/logout')).toBe(false);
  });

  it('still classifies every other endpoint under the same prefix as OAuth', () => {
    // The exclusion must not swallow the routes the broad prefix exists FOR: /auth and /certs are
    // this authority's actual path segments for "authorize" and "jwks", neither literally named
    // that, so the specific verb list below could never have caught them on its own.
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/auth')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/auth/consent')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/token')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/token/introspect')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/revoke')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/userinfo')).toBe(true);
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/protocol/oidc/certs')).toBe(true);
  });

  it('still classifies discovery and the verb-named routes outside that prefix', () => {
    expect(isOAuthSurface('/.well-known/openid-configuration')).toBe(true);
    expect(isOAuthSurface('/realms/LeafyIdp/auth/bc-authorize')).toBe(true);
  });

  it('leaves an ordinary administrative path unclassified', () => {
    expect(isOAuthSurface('/api/v1/realms/LeafyIdp/scim/Users/abc')).toBe(false);
    expect(isOAuthSurface('/api/v1/admin/resource-servers/leafypay/permissions')).toBe(false);
  });
});
