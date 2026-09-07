/**
 * What a token says about HOW the person authenticated.
 *
 * Three claims, and they answer different questions. `auth_time` says when, `acr` says how strongly,
 * `amr` says by what means. A resource server needs all three to demand a step-up for a sensitive
 * operation without knowing anything about how sessions work here.
 *
 * The sources already exist and previously went nowhere: `PrincipalResolution.assuranceLevel` is the
 * NIST SP 800-63 level the method actually achieved, and `PrincipalResolution.method` is the method
 * that achieved it.
 */

/** RFC 8176 authentication method reference values, for the methods this authority implements. */
const AMR_BY_METHOD: Record<string, string> = {
  // A shared secret the person knows.
  password: 'pwd',
  /**
   * Proof of possession of a software-secured key.
   *
   * `swk` rather than `hwk` because the key lives in browser storage, not in a hardware
   * authenticator. Claiming `hwk` would overstate the assurance to every resource server reading it.
   */
  public_key: 'swk',
  totp: 'otp',
  recovery_code: 'otp',
  /**
   * A client secret is structurally a shared secret, which is what `pwd` names.
   *
   * The credential model already takes this position: a `client_id` plus a `client_secret`
   * authenticates a party exactly as a username plus a password does.
   */
  client_secret: 'pwd',
};

/**
 * The `amr` array for one or more methods used in a single authentication.
 *
 * `mfa` is appended when more than one distinct factor was involved, per RFC 8176, because a
 * resource server asking "was this multi-factor" should not have to know which combinations count.
 */
export function amrFor(...methods: Array<string | undefined>): string[] {
  const values = [...new Set(
    methods
      .filter((method): method is string => Boolean(method))
      .map((method) => AMR_BY_METHOD[method])
      .filter(Boolean),
  )];
  if (values.length > 1) values.push('mfa');
  return values;
}

/**
 * The authentication context a session carries, so issuing a token needs no credential read.
 *
 * Resolved once at sign-in and stored, rather than re-derived per issuance: the question is what
 * happened when this session was established, and that answer cannot change afterwards. Re-deriving
 * it from the credential as it stands today would report the credential's CURRENT assurance for an
 * authentication that happened under the old one.
 */
export interface AuthenticationContext {
  /** NIST SP 800-63 authenticator assurance, carried as the OIDC `acr`. */
  acr?: string;
  /** RFC 8176 method references, carried as the OIDC `amr`. */
  amr?: string[];
  /** The credential that authenticated. Closes the trail from a session to the factor used. */
  credentialId?: string;
}
