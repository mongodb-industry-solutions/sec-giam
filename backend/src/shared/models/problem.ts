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

// Maps a transport status onto the RFC's own code set rather than inventing one per failure.
export function oauthError(status: number, description?: string): OAuthError {
  const code = status === 401 ? 'invalid_client'
    : status === 403 ? 'access_denied'
      : status === 404 ? 'invalid_request'
        : status >= 500 ? 'server_error'
          : 'invalid_request';
  return { error: code, ...(status < 500 && description ? { error_description: description } : {}) };
}
