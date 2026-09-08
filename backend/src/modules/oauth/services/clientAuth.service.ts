import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { OAuthClient, isConfidential, clientFromCredential } from '../models/client.model';
import { CredentialRecord, isUsable } from '../../directory/models/credential.model';
import { RealmRecord, enforcementFor } from '../../realm/models/realm.model';
import { newMeta } from '../../../shared/models/base.model';
import { SecurityEventService, hashIp } from '../../audit/services/securityEvent.service';

export interface PresentedClientCredentials {
  clientId?: string;
  clientSecret?: string;
}

/**
 * The only authority a soft admission carries.
 *
 * `openid` and nothing else: enough to prove who signed in, not enough to reach anything. Soft mode
 * has to admit a client WITHOUT handing it what registration is for, or registration buys nothing
 * and nobody completes it.
 */
export const SOFT_ADMISSION_SCOPE = 'openid';

/** The grants a soft admission may use. Never the privileged ones, which have no onboarding excuse. */
const SOFT_ADMISSION_GRANTS: OAuthClient['grantTypes'] = ['authorization_code', 'client_credentials'];

/**
 * The stand-in record for a client that has not registered yet.
 *
 * Built in memory and NEVER written. Persisting it would turn an onboarding ramp into a self-service
 * registration endpoint, and the whole point is that the registration is still outstanding.
 */
export function provisionalClient(
  realm: RealmRecord,
  clientId: string,
  redirectUris: string[] = [],
): OAuthClient {
  return {
    realmId: realm.realmId,
    tenantId: realm.tenantId,
    clientId,
    clientName: `${clientId} (not registered)`,
    clientType: 'public',
    redirectUris,
    grantTypes: SOFT_ADMISSION_GRANTS,
    scope: SOFT_ADMISSION_SCOPE,
    // A public client relies on PKCE, so it is required rather than optional even here.
    requirePkce: true,
    tokenEndpointAuthMethod: 'none',
    status: 'active',
    meta: newMeta('Credential'),
  };
}

/**
 * The evidence a soft admission leaves behind.
 *
 * Named so an operator can list exactly who still has to register, from which address and against
 * which endpoint, and see what the reduction cost them. A mode that admits silently is the mode
 * nobody ever turns off.
 */
export async function recordSoftAdmission(db: Db, realm: RealmRecord, input: {
  clientId: string;
  endpoint: string;
  address?: string;
}): Promise<void> {
  await new SecurityEventService(db).record({
    realmId: realm.realmId,
    tenantId: realm.tenantId,
    action: 'client.soft_admission',
    outcome: 'success',
    category: 'client_registration',
    clientId: input.clientId,
    cause: 'client_not_registered',
    ...(hashIp(input.address) ? { ipHash: hashIp(input.address) } : {}),
    detail: {
      mode: 'soft',
      endpoint: input.endpoint,
      presentedClientId: input.clientId,
      grantedScope: SOFT_ADMISSION_SCOPE,
      reduction: 'no permissions claim, no roles claim, no refresh token, scope reduced to openid',
      remedy: `Register "${input.clientId}" in realm "${realm.name}", then return the realm to strict.`,
    },
  });
}

/**
 * Client authentication at the token endpoint, RFC 6749 §2.3.
 *
 * HTTP Basic first, because the specification says a server MUST support it and a client is entitled
 * to assume so; the form body is the documented alternative.
 */
export function readClientCredentials(
  authorization: string | undefined,
  body: Record<string, unknown>,
): PresentedClientCredentials {
  if (authorization?.startsWith('Basic ')) {
    const decoded = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    if (separator > 0) {
      // Percent-decoded per RFC 6749 §2.3.1: the credentials are form-encoded before being base64'd,
      // so a secret containing a reserved character arrives wrong if this step is skipped.
      return {
        clientId: decodeURIComponent(decoded.slice(0, separator)),
        clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
      };
    }
  }
  return {
    clientId: typeof body.client_id === 'string' ? body.client_id : undefined,
    clientSecret: typeof body.client_secret === 'string' ? body.client_secret : undefined,
  };
}

/**
 * The one read every other module uses to resolve a client.
 *
 * Exported as a function rather than requiring the service, because most callers want the
 * registration and not the authentication around it, and because a single reader is what keeps the
 * `oauth_client` filter from being restated at eight call sites where one could be forgotten.
 * Without that filter a password credential could answer a client lookup.
 */
export async function findOAuthClient(
  db: Db,
  realmId: string,
  clientId: string,
): Promise<OAuthClient | null> {
  const found = await db
    .collection<CredentialRecord>(CREDENTIAL_COLLECTION)
    .find({ realmId, clientId, type: 'oauth_client' }, { projection: { _id: 0 } })
    .toArray();
  const usable = found
    .filter((credential) => isUsable(credential))
    .sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''));
  return usable[0] ? clientFromCredential(usable[0]) : null;
}

/** Every client registered in a realm, one entry per `clientId` however many secrets it holds. */
export async function listOAuthClients(db: Db, realmId: string): Promise<OAuthClient[]> {
  const found = await db
    .collection<CredentialRecord>(CREDENTIAL_COLLECTION)
    .find({ realmId, type: 'oauth_client' }, { projection: { _id: 0 } })
    .toArray();
  const newestByClientId = new Map<string, CredentialRecord>();
  for (const credential of found) {
    if (!credential.clientId) continue;
    const held = newestByClientId.get(credential.clientId);
    if (!held || (credential.createdAt ?? '') > (held.createdAt ?? '')) {
      newestByClientId.set(credential.clientId, credential);
    }
  }
  return [...newestByClientId.values()].map(clientFromCredential);
}

export class ClientAuthService {
  constructor(private readonly db: Db) {}

  /**
   * Every credential registered under this `clientId`, whatever its status.
   *
   * A LIST rather than one record, because rotating a secret with an overlap window means two are
   * active at once. Ordered newest first, so the secret a deployment has just been given is the one
   * tried first and the old one is only reached by a caller that has not moved yet.
   *
   * Returns the INACTIVE ones too, and that is not laziness. "No registration exists" and "the
   * registration is revoked" must stay distinguishable: filtering here would make a revoked client
   * look unregistered, and soft admission would then admit the one client an operator has
   * explicitly turned off.
   */
  private async registrations(realmId: string, clientId: string): Promise<CredentialRecord[]> {
    const found = await this.db
      .collection<CredentialRecord>(CREDENTIAL_COLLECTION)
      .find({ realmId, clientId, type: 'oauth_client' }, { projection: { _id: 0 } })
      .toArray();
    return found.sort((a, b) => (b.createdAt ?? '').localeCompare(a.createdAt ?? ''));
  }

  async find(realmId: string, clientId: string): Promise<OAuthClient | null> {
    const [registration] = await this.registrations(realmId, clientId);
    return registration ? clientFromCredential(registration) : null;
  }

  /**
   * Resolves and, where required, authenticates the client.
   *
   * A confidential client MUST authenticate for EVERY grant (RFC 6749 §3.2.1), not only when it
   * happens to send a secret. Validating a secret only when one is present is the defect where
   * omitting it bypasses authentication entirely, which is worse than not checking at all because it
   * looks like it is checking.
   *
   * A public client presents no secret and relies on PKCE, which is why `requirePkce` is not optional
   * for one.
   *
   * `allowSoftAdmission` lets a realm in soft mode admit a client it has never seen, with the
   * reduced authority above. It relaxes EXACTLY ONE thing: not being registered. A known client with
   * a wrong secret, a suspended one, a revoked one and a grant the client does not hold are all
   * still refused, in both modes, because none of those is an onboarding gap.
   */
  async authenticate(
    realm: RealmRecord,
    presented: PresentedClientCredentials,
    options: { requireAuthentication: boolean; allowSoftAdmission?: boolean },
  ): Promise<{ client: OAuthClient; softAdmitted: boolean } | { error: string; description: string }> {
    if (!presented.clientId) {
      return { error: 'invalid_client', description: 'client_id is required' };
    }

    const registrations = await this.registrations(realm.realmId, presented.clientId);
    if (registrations.length === 0) {
      const soft = options.allowSoftAdmission && enforcementFor(realm) === 'soft';
      if (!soft) return { error: 'invalid_client', description: 'unknown client' };
      return { client: provisionalClient(realm, presented.clientId), softAdmitted: true };
    }

    // Registered but turned off. Refused in BOTH modes and BEFORE soft admission is considered:
    // being suspended or revoked is not an onboarding gap, and soft mode relaxes exactly one thing.
    const usable = registrations.filter((credential) => isUsable(credential));
    if (usable.length === 0) {
      return { error: 'invalid_client', description: 'client is not active' };
    }

    const client = clientFromCredential(usable[0]);
    const confidential = isConfidential(client);
    if (options.requireAuthentication && confidential && !presented.clientSecret) {
      return { error: 'invalid_client', description: 'client authentication required' };
    }

    if (presented.clientSecret) {
      if (!confidential) {
        // A public client presenting a secret is a misconfiguration worth naming: it will fail
        // intermittently otherwise, depending on which code path examines the secret.
        return { error: 'invalid_client', description: 'this client is public and holds no secret' };
      }

      // EITHER active secret is accepted, which is what makes a rotation window a window. Every
      // candidate is compared even after one matches, so the time taken does not reveal which
      // secret was the right one.
      let matched: CredentialRecord | null = null;
      for (const registration of usable) {
        if (!registration.hash) continue;
        const valid = await bcrypt.compare(presented.clientSecret, registration.hash);
        if (valid && !matched) matched = registration;
      }
      if (!matched) return { error: 'invalid_client', description: 'invalid client_secret' };
      return { client: clientFromCredential(matched), softAdmitted: false };
    }

    return { client, softAdmitted: false };
  }

  /** Whether the client is registered for this grant. Refused rather than ignored. */
  allowsGrant(client: OAuthClient, grantType: string): boolean {
    return client.grantTypes.includes(grantType as OAuthClient['grantTypes'][number]);
  }
}
