import { config } from '../../../config';
import { GrantType } from '../models/client.model';

/**
 * What an ordinary principal may register for itself, and what only an administrator may.
 *
 * Self-service registration is the point of this surface: a person building an integration should
 * not need an operator to mint them a client. It is also an abuse surface, so the ordinary path is
 * narrowed deliberately rather than trusted. Everything refused here is still available to a caller
 * holding the administrative permission, so the constraint limits reach, not capability.
 */

export interface RegistrationRefusal {
  refused: string;
}

export function isRefusal(value: unknown): value is RegistrationRefusal {
  return typeof value === 'object' && value !== null && 'refused' in value;
}

/**
 * The scopes an ordinary owner may ask for.
 *
 * Only the sign-in scopes. A self-registered client asking for an application's business scopes
 * would be requesting authority its owner may not hold, and the consent screen is not the place to
 * discover that. Anything wider is an administrator's decision.
 */
export const SELF_SERVICE_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

/**
 * The grants an ordinary owner may ask for.
 *
 * `client_credentials` is deliberately absent: it is a machine identity that acts with no person
 * behind it, and handing one out through self-service turns a user account into an issuer of service
 * principals. Token exchange and backchannel authentication are excluded for the same reason.
 */
export const SELF_SERVICE_GRANTS: GrantType[] = ['authorization_code', 'refresh_token'];

/**
 * How many clients one principal may register.
 *
 * Five: enough for a real integration plus its development and staging copies, low enough that a
 * scripted abuse stops being useful. Not a security boundary on its own, a brake. An administrator
 * is not capped, because a cap on the person who administers the cap is theatre.
 */
export const SELF_SERVICE_CLIENT_LIMIT = 5;

/** Loopback and the development origins, where plain HTTP is the only thing that works. */
function isDevelopmentHost(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

/** The hosts this platform serves from, which a self-registered client must never claim. */
export function firstPartyHosts(): Set<string> {
  const hosts = new Set<string>();
  for (const candidate of [config.server.publicUrl, config.server.baseUrl]) {
    if (!candidate) continue;
    try { hosts.add(new URL(candidate).host.toLowerCase()); } catch { /* not a URL, nothing to add */ }
  }
  return hosts;
}

export function hostOf(uri: string): string {
  try { return new URL(uri).host.toLowerCase(); } catch { return ''; }
}

/**
 * Checks the redirect URIs an ordinary owner asked for.
 *
 * This authority matches a redirect exactly and never by prefix, which removes a whole class of
 * escape. What it does not remove is a self-registered client pointing at an origin the person
 * signing in already trusts, so a host this platform serves from is refused outright, as is a
 * wildcard, a fragment and plain HTTP anywhere but a development origin.
 */
export function checkRedirectUris(
  uris: string[],
  reserved: Set<string>,
): RegistrationRefusal | { uris: string[] } {
  if (uris.length === 0) {
    return { refused: 'At least one redirect URI is required, and it is matched exactly.' };
  }

  for (const uri of uris) {
    if (uri.includes('*')) {
      return { refused: `"${uri}" contains a wildcard. Redirect URIs are matched exactly, so every address must be written in full.` };
    }

    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      return { refused: `"${uri}" is not an absolute URI.` };
    }

    if (parsed.hash) {
      return { refused: `"${uri}" carries a fragment, which is never sent to a redirect endpoint.` };
    }
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isDevelopmentHost(parsed.hostname))) {
      return { refused: `"${uri}" is not HTTPS. Plain HTTP is accepted only on a loopback address.` };
    }
    if (reserved.has(parsed.host.toLowerCase())) {
      return { refused: `"${uri}" points at a host this platform serves from, which would place your application inside an origin people already trust.` };
    }
  }

  return { uris };
}

/** Narrows the requested scopes, refusing rather than silently dropping what it will not grant. */
export function checkScopes(requested: string[]): RegistrationRefusal | { scopes: string[] } {
  const beyond = requested.filter((scope) => !SELF_SERVICE_SCOPES.includes(scope));
  if (beyond.length > 0) {
    return { refused: `Scopes not available to a self-registered application: ${beyond.join(', ')}.` };
  }
  return { scopes: requested.length > 0 ? requested : ['openid'] };
}

/** Narrows the requested grant types the same way, and for the same reason. */
export function checkGrantTypes(requested: string[]): RegistrationRefusal | { grantTypes: GrantType[] } {
  const beyond = requested.filter((grant) => !SELF_SERVICE_GRANTS.includes(grant as GrantType));
  if (beyond.length > 0) {
    return { refused: `Grant types not available to a self-registered application: ${beyond.join(', ')}.` };
  }
  return { grantTypes: requested.length > 0 ? requested as GrantType[] : ['authorization_code'] };
}
