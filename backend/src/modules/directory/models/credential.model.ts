import { Meta, Scoped, OwnerRef } from '../../../shared/models/base.model';
import { RoleHolding } from './principal.model';
import type { PlatformEnvironment } from '@leafypay/platform-links';

/**
 * One collection for every authentication factor, discriminated by type.
 *
 * Separating credentials from the principal is what lets a subject hold several factors, lets one be
 * revoked without touching the others, and lets a new factor type arrive without altering the
 * identity record. It is also what stops a directory read from carrying credential material by
 * accident: the two are simply not in the same document.
 */

/**
 * Every kind of thing that identifies a principal.
 *
 * `oauth_client` is here because a `client_id` plus a `client_secret` is structurally a username
 * plus a password: it authenticates a party to this server. Its redirect URIs, grant types and
 * scopes are metadata OF that credential rather than a separate kind of record, and treating it as
 * one means disabling an application is the same operation as revoking an API key instead of a
 * special case with its own code path.
 */
export type CredentialType =
  | 'password'
  | 'public_key'
  | 'client_secret'
  | 'totp'
  | 'recovery_code'
  | 'api_key'
  | 'oauth_client';

/** The most active `oauth_client` credentials one `clientId` may have at once. */
export const MAX_ACTIVE_CLIENT_SECRETS = 2;

/** NIST SP 800-63 authenticator assurance. Recorded per credential, since it is a property of one. */
export interface Assurance {
  level: 'aal1' | 'aal2' | 'aal3';
  method: string;
  verifiedAt?: string;
}

/**
 * What an `oauth_client` credential carries beyond the credential fields themselves.
 *
 * Type specific and unindexed: nothing here is ever a query predicate, because a client is always
 * resolved by `clientId` and then read whole. Keeping it in one sub document is what stops the
 * credential collection growing a column per application type.
 */
export interface OAuthClientMetadata {
  clientName: string;
  clientType: 'confidential' | 'public';
  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  grantTypes: string[];
  scopes: string[];
  requirePkce: boolean;
  tokenEndpointAuthMethod:
    | 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'tls_client_auth' | 'none';
  applicationType?: 'web' | 'native' | 'service';
  tokenPolicy?: Record<string, unknown>;
  logoUri?: string;
  clientUri?: string;
  /**
   * Where THIS application answers, per environment. Declared by the application, on its own record.
   *
   * The same shape a provider arrangement already uses for the same question, and for the same
   * reason: one registration has to serve a laptop, staging and production, and the alternative is a
   * host frozen into whichever one happened to be seeded. It is on the REGISTRATION and not in the
   * authority's configuration because adding an application is then a registration, not a
   * redeployment of the authority, and because each application owns what is true about itself.
   *
   * Partial on purpose: an application that is not deployed to an environment has no entry for it,
   * and that must read as "not published here" rather than as an empty address.
   */
  baseUrlByEnvironment?: Partial<Record<PlatformEnvironment, string>>;
  demoRoster?: string[];
  /** Resource servers a token for this client is addressed to. Declared, never inferred. */
  audience?: string[];
  firstParty?: boolean;
  backchannel?: Record<string, unknown>;
  /** RFC 8705: the certificate a client is bound to, when it authenticates with one. */
  mtls?: { certificateThumbprint?: string };
  claimMappings?: Record<string, string>;

  /**
   * Where this application wants to be told about identity lifecycle changes.
   *
   * DECLARED here as of v40 because it was being QUERIED and was not declared anywhere, so the
   * query matched nothing and no provisioning notice had ever been delivered, before or after the
   * consolidation. A filter on an undeclared field is the worst kind of dead code: it reads as a
   * working feature and fails silently forever.
   *
   * Absent means this client does not receive notices, which is the honest default: outbound
   * provisioning is opt-in, and a notice sent to an application that never asked for one is an
   * unsolicited push of identity data.
   */
  provisioning?: {
    endpoint: string;
    /** Which lifecycle operations to send. Absent means all three. */
    events?: Array<'create' | 'update' | 'deactivate'>;
  };
}

export interface CredentialRecord extends Scoped {
  credentialId: string;
  subjectId: string;
  type: CredentialType;

  /**
   * The principal this credential ACTS AS, and which answers for what it does.
   *
   * Required, and flat: it always terminates at a principal. Making an application a principal
   * instead would allow a principal to own a principal, which is recursive, and every ownership
   * query would then have to decide how deep to look.
   *
   * This is the `sub` of a `client_credentials` token, so it must be a principal of kind `service`
   * or `workload`. That is better than an abstract application entity, not a workaround: a service
   * token is then attributable to a real subject with a lifecycle and an owner.
   *
   * Deliberately SINGULAR and deliberately not the same thing as `administrators` below. A token has
   * exactly one subject, so the identity a credential acts as cannot be a set; who may administer
   * the registration can be, and conflating the two is what makes the question look unanswerable.
   */
  ownerId: string;

  /**
   * Who may administer this credential. A SET, because two people sharing one integration is normal.
   *
   * Every administrator holds the same authority: read, edit, rotate the secret, withdraw. There is
   * no primary, because a hierarchy raises a question this authority cannot answer, namely what
   * happens to the application when the primary leaves. It must never reach zero, or the credential
   * becomes unadministrable and only an operator credential can touch it again.
   *
   * Still flat and still terminating at a principal, so the ADR's structural guarantee holds: this
   * widens WHO MANAGES it, never what it is attributable to.
   */
  administrators?: OwnerRef[];

  /**
   * ADR-004: what THIS credential may do, narrower than its owning principal if it says anything
   * at all.
   *
   * Same shape a principal's own holdings take, resolved through the same pipeline (composition,
   * expiry, realm scoping): a credential is not a second kind of authority, it is the same kind,
   * asked of a different document.
   *
   * Absent or empty is not "this credential can do nothing": it is "this credential has nothing OF
   * ITS OWN to say", which resolves to the owning principal's roles exactly as every credential
   * behaved before this field existed. Present and non-empty REPLACES the principal's roles for a
   * token authenticated with this credential; it is not added on top. A service principal with one
   * broad role and three credentials, one of them scoped down to a single narrow capability, is the
   * case this exists for: the principal is not diminished, and neither are its other credentials.
   */
  roles?: RoleHolding[];

  /** The authentication path this credential belongs to, when it belongs to one. */
  domainId?: string;

  /** The wire identifier for an `oauth_client` or an `api_key`. Not unique on its own: see below. */
  clientId?: string;
  /**
   * The leading, non-secret part of a key, so an operator can tell two apart in a list without
   * either being recoverable from what they are looking at.
   */
  secretPrefix?: string;

  /** Type-specific, unindexed. Present for `oauth_client`. */
  metadata?: OAuthClientMetadata;

  /** bcrypt, for `password`, `client_secret`, `api_key` and `oauth_client`. Salted, so it is verified rather than looked up. */
  hash?: string;

  /** For `public_key`: what the authenticator registered. Public material only, by definition. */
  publicKeyPem?: string;
  algorithm?: 'ES256' | 'RS256';
  /**
   * The authenticator's own counter.
   *
   * A signature arriving with a counter at or below the stored one means the same authenticator
   * appears to exist twice, which is the definition of a cloned device.
   */
  signCount?: number;

  label?: string;
  /**
   * `suspended` is reversible and `revoked` is terminal, and the difference matters: suspending an
   * application is an operational decision somebody may undo, while revoking one is a statement that
   * the credential must never work again. Collapsing them would make an undo look like a new grant.
   */
  status: 'active' | 'suspended' | 'revoked';
  assurance: Assurance;

  createdAt: string;
  lastUsedAt?: string;
  expiresAt?: string;
  meta: Meta;
}

export function isUsable(credential: Pick<CredentialRecord, 'status' | 'expiresAt'>, now = new Date()): boolean {
  // Only `active` is usable. Suspended and revoked both refuse; the distinction is about whether the
  // refusal can be lifted, not about whether it applies.
  if (credential.status !== 'active') return false;
  // An expiry that has passed is a refusal, not a warning: a credential is either current or it is not.
  return !credential.expiresAt || Date.parse(credential.expiresAt) > now.getTime();
}

/**
 * Why `{realmId, clientId}` is NOT uniquely indexed.
 *
 * Rotating a client secret with an overlap window means two credentials for one `clientId` are
 * active at the same time, each with its own hash, so authentication accepts either while the
 * deployment moves from the old secret to the new one. A unique index on the pair would make the
 * overlap impossible and rotation would be back to a single field that has to be swapped
 * instantaneously, which is the limitation this change exists to remove.
 *
 * Uniqueness still holds where it means something: `credentialId` is globally unique, and the
 * number of concurrently active secrets per `clientId` is capped here rather than by an index,
 * because the rule is "at most two" and an index can only express "exactly one".
 */
export function withinActiveSecretCap(activeCount: number): boolean {
  return activeCount < MAX_ACTIVE_CLIENT_SECRETS;
}
