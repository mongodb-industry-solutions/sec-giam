import { Meta, Scoped, OwnerRef } from '../../../shared/models/base.model';
import { CredentialRecord, OAuthClientMetadata } from '../../directory/models/credential.model';

/**
 * The OAuth client, in RFC 7591 vocabulary.
 *
 * NOT a stored record any more. An OAuth client registration is a credential of type
 * `oauth_client`, because a `client_id` plus a `client_secret` authenticates a party to this server
 * exactly as a username plus a password does. What lives here is the flat VIEW the protocol code
 * reads, projected from that credential in one place by `clientFromCredential`.
 *
 * A view rather than `metadata.` prefixes at sixty call sites: the protocol code asks about redirect
 * URIs and grant types, not about where they are stored, and one mapper is the seam where the two
 * meet. The projection reads the new shape only. Nothing here falls back to the old collection.
 */

export type GrantType =
  | 'authorization_code'
  | 'client_credentials'
  | 'refresh_token'
  | 'urn:ietf:params:oauth:grant-type:token-exchange'
  | 'urn:openid:params:grant-type:ciba';

export type BackchannelDeliveryMode = 'poll' | 'ping' | 'push';

export interface OAuthClient extends Scoped {
  clientId: string;
  /** bcrypt. Absent on a public client, which relies on PKCE instead. */
  clientSecretHash?: string;
  clientSecretPrefix?: string;
  clientName: string;
  clientType: 'confidential' | 'public';

  redirectUris: string[];
  postLogoutRedirectUris?: string[];
  grantTypes: GrantType[];
  /** Space-delimited, per RFC 7591, rather than an array. The standard's shape, not a convenience. */
  scope: string;

  requirePkce: boolean;
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'tls_client_auth' | 'none';
  applicationType?: 'web' | 'native' | 'service';

  /** Overrides the realm default when present. */
  tokenPolicy?: {
    accessTokenTtlSeconds?: number;
    refreshTokenTtlSeconds?: number;
  };

  logoUri?: string;
  clientUri?: string;

  /**
   * Which roles this client's sign-in screen offers as demo personas.
   *
   * Scoped per client because the useful set differs: an application's own staff are irrelevant on a
   * third party's screen, and an oversight role has no business being offered on a screen meant to
   * demonstrate an ordinary user. Roles rather than named people, so the list survives the demo
   * population changing. Absent means every featured persona in the realm, which is the old behaviour.
   */
  demoRoster?: string[];

  /**
   * Whether this client IS the authority, and so has nobody to ask.
   *
   * Absent means it is not, which is why consent is the default rather than the exception: a client
   * added without thinking about this asks, and asking one time too many is a far smaller failure
   * than an application quietly obtaining an identity nobody agreed to hand over.
   *
   * The identities belong to this authority, not to the applications that rely on it, so every
   * application is a third party here, including the platform's own console. Only this authority's
   * own console sets the flag, because asking a person to consent to us reading their profile with us
   * is a question with no meaning.
   */
  firstParty?: boolean;

  backchannel?: {
    deliveryMode: BackchannelDeliveryMode;
    notificationEndpoint?: string;
  };

  /** RFC 8705: the certificate this client is bound to, when tokens are sender-constrained. */
  mtls?: {
    certificateThumbprint: string;
  };

  status: 'active' | 'suspended' | 'revoked';

  /**
   * Who administers this registration. A SET, because two people sharing one integration is normal.
   *
   * Every owner holds the same authority: read, edit, rotate the secret, withdraw. There is no
   * primary owner, because a hierarchy raises a question this authority has no answer to, namely what
   * happens to the application when the primary leaves. A registration must never reach zero owners,
   * or it becomes unadministrable and only an operator credential can touch it again.
   *
   * Each entry is the only back-reference to a consuming application's record, and it is an opaque
   * string. The authority does not resolve it and does not know what it names. The display name is
   * copied at registration so an audit trail can say who a token was issued to without calling anyone.
   */
  owners?: OwnerRef[];

  /** Upstream role names this client's claims map to, for a client that federates its own users. */
  claimMappings?: Record<string, string>;

  meta: Meta;
}

/** Retired here so the seeder unsets them and nothing writes them again: `owner` became `owners`. */
export const RETIRED_CLIENT_FIELDS: readonly string[] = ['owner'];

export function scopesOf(client: Pick<OAuthClient, 'scope'>): string[] {
  return client.scope.split(' ').filter(Boolean);
}

export function isConfidential(client: Pick<OAuthClient, 'clientSecretHash'>): boolean {
  return typeof client.clientSecretHash === 'string' && client.clientSecretHash.length > 0;
}

/**
 * The one place a stored credential becomes the client the protocol code reads.
 *
 * `scope` is rebuilt space-delimited because that is RFC 7591's shape and the standard's shape is
 * what the wire contract owes, even though the stored form is an array.
 */
export function clientFromCredential(credential: CredentialRecord): OAuthClient {
  const metadata = credential.metadata ?? ({} as OAuthClientMetadata);
  return {
    realmId: credential.realmId,
    tenantId: credential.tenantId,
    clientId: credential.clientId as string,
    ...(credential.secretHash ? { clientSecretHash: credential.secretHash } : {}),
    ...(credential.secretPrefix ? { clientSecretPrefix: credential.secretPrefix } : {}),
    clientName: metadata.clientName ?? (credential.clientId as string),
    clientType: metadata.clientType ?? 'public',
    redirectUris: metadata.redirectUris ?? [],
    ...(metadata.postLogoutRedirectUris ? { postLogoutRedirectUris: metadata.postLogoutRedirectUris } : {}),
    grantTypes: (metadata.grantTypes ?? []) as GrantType[],
    scope: (metadata.scopes ?? []).join(' '),
    requirePkce: metadata.requirePkce ?? true,
    tokenEndpointAuthMethod: metadata.tokenEndpointAuthMethod ?? 'none',
    ...(metadata.applicationType ? { applicationType: metadata.applicationType } : {}),
    ...(metadata.tokenPolicy ? { tokenPolicy: metadata.tokenPolicy as OAuthClient['tokenPolicy'] } : {}),
    ...(metadata.logoUri ? { logoUri: metadata.logoUri } : {}),
    ...(metadata.clientUri ? { clientUri: metadata.clientUri } : {}),
    ...(metadata.demoRoster ? { demoRoster: metadata.demoRoster } : {}),
    ...(metadata.firstParty !== undefined ? { firstParty: metadata.firstParty } : {}),
    ...(metadata.backchannel ? { backchannel: metadata.backchannel as OAuthClient['backchannel'] } : {}),
    ...(metadata.mtls ? { mtls: metadata.mtls as OAuthClient['mtls'] } : {}),
    ...(metadata.claimMappings ? { claimMappings: metadata.claimMappings } : {}),
    // Who may administer the registration. Distinct from the principal it acts as, which is
    // `ownerSubjectId` and is a token subject rather than a set of people.
    owners: credential.administrators ?? [{ kind: 'principal', ref: credential.ownerSubjectId } as OwnerRef],
    status: credential.status,
    meta: credential.meta,
  };
}

/** The metadata sub document a client registration writes. The inverse of the projection above. */
export function clientMetadata(client: Partial<OAuthClient>): OAuthClientMetadata {
  return {
    clientName: client.clientName ?? '',
    clientType: client.clientType ?? 'public',
    redirectUris: client.redirectUris ?? [],
    ...(client.postLogoutRedirectUris ? { postLogoutRedirectUris: client.postLogoutRedirectUris } : {}),
    grantTypes: client.grantTypes ?? [],
    scopes: client.scope ? client.scope.split(' ').filter(Boolean) : [],
    // Defaults to REQUIRED. The seeded default was false, which is below the baseline RFC 9700 sets.
    requirePkce: client.requirePkce ?? true,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod ?? 'none',
    ...(client.applicationType ? { applicationType: client.applicationType } : {}),
    ...(client.tokenPolicy ? { tokenPolicy: client.tokenPolicy as Record<string, unknown> } : {}),
    ...(client.logoUri ? { logoUri: client.logoUri } : {}),
    ...(client.clientUri ? { clientUri: client.clientUri } : {}),
    ...(client.demoRoster ? { demoRoster: client.demoRoster } : {}),
    ...(client.firstParty !== undefined ? { firstParty: client.firstParty } : {}),
    ...(client.backchannel ? { backchannel: client.backchannel as Record<string, unknown> } : {}),
    ...(client.mtls ? { mtls: client.mtls } : {}),
    ...(client.claimMappings ? { claimMappings: client.claimMappings } : {}),
  };
}
