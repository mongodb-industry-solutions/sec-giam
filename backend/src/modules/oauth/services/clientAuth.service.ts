import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';
import { ClientRecord, isConfidential } from '../models/client.model';

export interface PresentedClientCredentials {
  clientId?: string;
  clientSecret?: string;
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

export class ClientAuthService {
  constructor(private readonly db: Db) {}

  async find(realmId: string, clientId: string): Promise<ClientRecord | null> {
    return this.db
      .collection<ClientRecord>(CLIENT_COLLECTION)
      .findOne({ realmId, clientId }, { projection: { _id: 0 } });
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
   */
  async authenticate(
    realmId: string,
    presented: PresentedClientCredentials,
    options: { requireAuthentication: boolean },
  ): Promise<{ client: ClientRecord } | { error: string; description: string }> {
    if (!presented.clientId) {
      return { error: 'invalid_client', description: 'client_id is required' };
    }

    const client = await this.find(realmId, presented.clientId);
    if (!client) return { error: 'invalid_client', description: 'unknown client' };
    if (client.status !== 'active') return { error: 'invalid_client', description: 'client is not active' };

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
      const valid = await bcrypt.compare(presented.clientSecret, client.clientSecretHash as string);
      if (!valid) return { error: 'invalid_client', description: 'invalid client_secret' };
    }

    return { client };
  }

  /** Whether the client is registered for this grant. Refused rather than ignored. */
  allowsGrant(client: ClientRecord, grantType: string): boolean {
    return client.grantTypes.includes(grantType as ClientRecord['grantTypes'][number]);
  }
}
