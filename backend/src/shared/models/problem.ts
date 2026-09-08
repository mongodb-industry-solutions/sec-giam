// Error shapes. Two of them, and which one applies is decided by the surface, never by preference.
//
// A standard-defined endpoint answers with the specification's own error object: OAuth returns
// {error, error_description} per RFC 6749 §5.2, SCIM returns a SCIM error. Wrapping either in a house
// envelope breaks every conforming client, which is why it counts as a defect rather than a style.
// Everywhere else the answer is RFC 9457 problem+json.

/** RFC 9457 problem details. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
}

export const PROBLEM_SCHEMA = {
  $id: 'Problem',
  type: 'object',
  description: 'RFC 9457 problem details.',
  required: ['type', 'title', 'status'],
  additionalProperties: true,
  properties: {
    type: { type: 'string', description: 'A URI identifying the problem type.', examples: ['about:blank'] },
    title: { type: 'string', description: 'A short, human-readable summary.', examples: ['Not Found'] },
    status: { type: 'integer', description: 'The HTTP status code.', examples: [404] },
    detail: { type: 'string', description: 'An explanation specific to this occurrence.' },
    instance: { type: 'string', description: 'A URI identifying this occurrence.' },
  },
  examples: [{ type: 'about:blank', title: 'Not Found', status: 404 }],
} as const;

export function problem(status: number, title: string, detail?: string, instance?: string): Problem {
  return { type: 'about:blank', title, status, ...(detail && { detail }), ...(instance && { instance }) };
}

/** RFC 6749 §5.2 error response, the only acceptable shape on an OAuth endpoint. */
export interface OAuthError {
  error: string;
  error_description?: string;
}

export const OAUTH_ERROR_SCHEMA = {
  $id: 'OAuthError',
  type: 'object',
  description: 'RFC 6749 section 5.2 error response.',
  required: ['error'],
  additionalProperties: true,
  properties: {
    error: { type: 'string', description: 'The RFC 6749 error code.', examples: ['invalid_request'] },
    error_description: { type: 'string', description: 'Human-readable detail.' },
    error_uri: { type: 'string', description: 'A page describing the error.' },
  },
  examples: [{ error: 'invalid_request', error_description: 'grant_type is required' }],
} as const;

// The paths where a specification owns the error shape. Prefix matched, because a realm issuer path
// carries the realm name in the middle.
const OAUTH_PATH_PATTERNS = [
  /\/\.well-known\//,
  /\/protocol\/openid-connect\//,
  /\/(authorize|token|introspect|revoke|userinfo|bc-authorize|jwks)(\/|$|\?)/,
];

export function isOAuthSurface(url: string): boolean {
  const path = url.split('?')[0];
  return OAUTH_PATH_PATTERNS.some((pattern) => pattern.test(path));
}

/**
 * The RFC 6749 error codes, as a closed set.
 *
 * Closed on purpose: the specification defines exactly these, a client switches on them, and a code
 * outside the set is a code no conforming client can act on. Typing it is what stops one being
 * invented at a call site.
 *
 * `invalid_target` is RFC 8707 2.2, for a resource indicator the client may not address.
 */
export type OAuthErrorCode =
  // RFC 6749 5.2, the token endpoint.
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  // RFC 6749 4.1.2.1, the authorization endpoint.
  | 'access_denied'
  | 'unsupported_response_type'
  | 'server_error'
  | 'temporarily_unavailable'
  // OIDC Core 3.1.2.6.
  | 'unsupported_response_mode'
  | 'login_required'
  | 'consent_required'
  | 'interaction_required'
  // RFC 8707 2.2.
  | 'invalid_target'
  /**
   * The backchannel flow's own codes, OIDC CIBA 1.0 13.
   *
   * `authorization_pending` and `slow_down` are shared with the device grant, RFC 8628 3.5, and mean
   * the same thing in both: keep polling, and keep polling less often. A client MUST be able to tell
   * them apart from a real failure, which is the reason they are codes rather than descriptions.
   *
   * Added because typing the set closed rejected them, which is the check working: they were being
   * emitted as untyped strings and would have been just as invisible if one had been misspelled.
   */
  | 'authorization_pending'
  | 'slow_down'
  | 'expired_token'
  | 'unknown_user_id';

/**
 * One error, with the code stated by the caller.
 *
 * It used to DERIVE the code from the HTTP status, which meant the whole surface could only ever
 * emit `invalid_request`, `invalid_client`, `access_denied` or `server_error`. It was structurally
 * incapable of `invalid_grant`, `invalid_scope`, `unsupported_grant_type` and
 * `unsupported_response_type`, several call sites computed a precise cause that was then discarded,
 * and the token endpoint's own header comment claimed it returned `invalid_grant`, which it could
 * not. A client cannot distinguish "your code expired" from "your request was malformed" when both
 * arrive as `invalid_request`.
 *
 * The description is suppressed on a 5xx, because an internal failure message is not for a caller.
 */
export function oauthError(code: OAuthErrorCode, description?: string, status = 400): OAuthError {
  return { error: code, ...(status < 500 && description ? { error_description: description } : {}) };
}

/**
 * The code to use when only a transport status is known.
 *
 * The error handler is the one place that genuinely has nothing better: it catches a thrown failure
 * or a schema rejection, where no call site chose a code. Kept as its own function rather than as a
 * default, so a controller cannot reach it by omission.
 */
export function oauthErrorForStatus(status: number): OAuthErrorCode {
  if (status === 401) return 'invalid_client';
  if (status === 403) return 'access_denied';
  if (status >= 500) return 'server_error';
  return 'invalid_request';
}
