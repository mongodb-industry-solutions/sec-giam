import { PLATFORM_ENVIRONMENTS, platformEnvironment, type PlatformEnvironment } from '@leafypay/platform-links';
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
  /**
   * The `credential` document this view was projected from.
   *
   * ADR-004: this is what a decision resolves a credential-scoped grant against. Absent for
   * `provisionalClient`'s soft-admission stand-in, which is built in memory and never written and so
   * has no `credential` document to name; every OTHER client is projected by `clientFromCredential`
   * and always has one. Either way, an absent `credentialId` falls back to the owning principal's
   * roles exactly as every client behaved before this field existed.
   */
  credentialId?: string;
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

  /**
   * Which resource servers a token for this client is addressed to. RFC 9068 `aud`.
   *
   * DECLARED, because the fallback cannot be correct once a realm holds more than one application.
   * It names every resource server registered in the realm, so with a payment service and a bank in
   * one realm every token was addressed to both, and audience stopped separating anything.
   *
   * A token that names one audience is refused by the other, which is the whole point of the claim.
   */
  audience?: string[];

  /** Overrides the realm default when present. */
  tokenPolicy?: {
    accessTokenTtlSeconds?: number;
    refreshTokenTtlSeconds?: number;
  };

  /**
   * ABSOLUTE, always, whichever shape it was registered in.
   *
   * RFC 7591 defines `logo_uri` as a URL, and a consent screen renders it in a browser that has no
   * idea which application it belongs to, so it cannot be anything else on the way out. What a
   * registration may STORE is a path, bound here against `baseUrlByEnvironment`; see the resolver.
   */
  logoUri?: string;
  clientUri?: string;

  /** Where this application answers, per environment, as its own registration declares it. */
  baseUrlByEnvironment?: Partial<Record<PlatformEnvironment, string>>;

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

  /** Where to send identity lifecycle notices, when this application asked for them. */
  provisioning?: {
    endpoint: string;
    events?: Array<'create' | 'update' | 'deactivate'>;
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
/**
 * The application's logo as an absolute URL, bound to where it answers in THIS environment.
 *
 * Bound when the record is READ and not when it was written, because the same database is restored
 * across environments: a host written at seed time in one cluster is not where the application
 * answers in the next, and the result is a browser asked for an icon from an address that is not
 * serving one. The registration states the application's own addresses; this picks the one that
 * applies now.
 *
 * An absolute `logo_uri` is returned untouched, which is what a self-registered third party gives:
 * its own host is not this platform's to decide. A path with no address for this environment is
 * dropped rather than half-resolved, so a screen shows its neutral placeholder instead of a broken
 * image.
 */
export function resolveClientLogoUri(
  metadata: Pick<OAuthClientMetadata, 'logoUri' | 'baseUrlByEnvironment'>,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const declared = metadata.logoUri?.trim();
  if (!declared) return undefined;
  if (/^https?:\/\//i.test(declared)) return declared;
  const base = metadata.baseUrlByEnvironment?.[platformEnvironment(env)]?.trim();
  if (!base) return undefined;
  return `${base.replace(/\/$/, '')}/${declared.replace(/^\//, '')}`;
}

/**
 * An application's addresses, parsed and normalised, or the reason one is refused.
 *
 * A pattern is not validation: `https://[broken` matches one, and a base carrying a query or fragment
 * is worse, because the logo join appends a path to the STRING and the path then lands inside the
 * fragment, so the browser asks for the base path instead. Each value is parsed here, must be http(s),
 * must name a host, and may carry no credentials, query or fragment. It is stored without a trailing
 * slash, so the join writes exactly one.
 */
export function normalizeBaseUrls(
  input: Partial<Record<string, string>>,
): { urls: Partial<Record<PlatformEnvironment, string>> } | { refused: string } {
  const urls: Partial<Record<PlatformEnvironment, string>> = {};
  for (const [environment, raw] of Object.entries(input)) {
    if (!(PLATFORM_ENVIRONMENTS as readonly string[]).includes(environment)) {
      return { refused: `"${environment}" is not an environment this platform is deployed to` };
    }
    if (raw === undefined || raw.trim() === '') continue;
    let parsed: URL;
    try {
      parsed = new URL(raw.trim());
    } catch {
      return { refused: `The ${environment} address is not a valid URL` };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { refused: `The ${environment} address must be http or https` };
    }
    if (!parsed.hostname) return { refused: `The ${environment} address has no host` };
    if (parsed.username || parsed.password) {
      return { refused: `The ${environment} address must not carry credentials` };
    }
    if (parsed.search || parsed.hash) {
      return { refused: `The ${environment} address must not carry a query or a fragment` };
    }
    urls[environment as PlatformEnvironment] = `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;
  }
  return { urls };
}

export function clientFromCredential(credential: CredentialRecord): OAuthClient {
  const metadata = credential.metadata ?? ({} as OAuthClientMetadata);
  const logoUri = resolveClientLogoUri(metadata);
  return {
    realmId: credential.realmId,
    tenantId: credential.tenantId,
    credentialId: credential.credentialId,
    clientId: credential.clientId as string,
    ...(credential.hash ? { clientSecretHash: credential.hash } : {}),
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
    ...(logoUri ? { logoUri } : {}),
    ...(metadata.baseUrlByEnvironment ? { baseUrlByEnvironment: metadata.baseUrlByEnvironment } : {}),
    ...(metadata.clientUri ? { clientUri: metadata.clientUri } : {}),
    ...(metadata.demoRoster ? { demoRoster: metadata.demoRoster } : {}),
    ...(metadata.audience ? { audience: metadata.audience } : {}),
    ...(metadata.firstParty !== undefined ? { firstParty: metadata.firstParty } : {}),
    ...(metadata.backchannel ? { backchannel: metadata.backchannel as OAuthClient['backchannel'] } : {}),
    ...(metadata.mtls ? { mtls: metadata.mtls as OAuthClient['mtls'] } : {}),
    ...(metadata.provisioning ? { provisioning: metadata.provisioning } : {}),
    ...(metadata.claimMappings ? { claimMappings: metadata.claimMappings } : {}),
    // Who may administer the registration. Distinct from the principal it acts as, which is
    // `ownerId` and is a token subject rather than a set of people.
    owners: credential.administrators ?? [{ kind: 'principal', ref: credential.ownerId } as OwnerRef],
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
    ...(client.baseUrlByEnvironment ? { baseUrlByEnvironment: client.baseUrlByEnvironment } : {}),
    ...(client.clientUri ? { clientUri: client.clientUri } : {}),
    ...(client.demoRoster ? { demoRoster: client.demoRoster } : {}),
    ...(client.audience ? { audience: client.audience } : {}),
    ...(client.firstParty !== undefined ? { firstParty: client.firstParty } : {}),
    ...(client.backchannel ? { backchannel: client.backchannel as Record<string, unknown> } : {}),
    ...(client.mtls ? { mtls: client.mtls } : {}),
    ...(client.provisioning ? { provisioning: client.provisioning } : {}),
    ...(client.claimMappings ? { claimMappings: client.claimMappings } : {}),
  };
}
