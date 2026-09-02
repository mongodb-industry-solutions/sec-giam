import { Db } from 'mongodb';
import { createHmac } from 'crypto';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { JwtTokenFormat } from '../../oauth/services/jwtTokenFormat';
import { OAuthClient } from '../../oauth/models/client.model';

/**
 * Telling the other applications that a session ended.
 *
 * Ending a session in one place would leave every application still holding a valid token, so the
 * operation only means something if the others hear about it. The notification is a signed token
 * verified against the same published key set the receivers already use for access tokens, so single
 * sign-out introduces no new trust relationship and no new secret.
 *
 * Here rather than in a controller because more than one route ends a session: the protocol logout
 * endpoint and an administrator ending somebody's session from the console are the same act, and two
 * copies of this is how one of them quietly stops notifying anybody.
 */
export class LogoutNotifier {
  constructor(private readonly db: Db) {}

  private ring(): KeyRing {
    return new KeyRing(new MongoSigningKeyStore(this.db));
  }

  /** A logout token, signed by the realm and short lived: acted on immediately or it is stale. */
  private async logoutToken(
    issuer: string,
    realmId: string,
    audience: string,
    subjectId: string,
    sessionId: string,
  ): Promise<string> {
    const format = new JwtTokenFormat(this.ring(), realmId, 'logout+jwt');
    const kid = await this.ring().signingKid(realmId);
    const now = Math.floor(Date.now() / 1000);
    return format.issue({
      iss: issuer,
      aud: audience,
      sub: subjectId,
      iat: now,
      exp: now + 120,
      sid: sessionId,
      // The member that says this is a logout and not something else the authority signed.
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      jti: createHmac('sha256', sessionId).update(String(now)).digest('hex').slice(0, 32),
    }, kid);
  }

  /**
   * Delivers to each client, and never lets a delivery failure undo the logout.
   *
   * A receiver that is down must not keep a session alive. The bound on that case is the access
   * token lifetime, which is short, and the revocation is recorded here regardless.
   */
  async notify(
    clients: OAuthClient[],
    realm: { issuer: string; realmId: string },
    subjectId: string,
    sessionId: string,
  ): Promise<{ delivered: string[]; failed: string[] }> {
    const delivered: string[] = [];
    const failed: string[] = [];

    await Promise.all(clients.map(async (client) => {
      const endpoint = client.backchannel?.notificationEndpoint;
      if (!endpoint) return;
      try {
        const token = await this.logoutToken(realm.issuer, realm.realmId, client.clientId, subjectId, sessionId);
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ logout_token: token }),
          signal: AbortSignal.timeout(3000),
        });
        (response.ok ? delivered : failed).push(client.clientId);
      } catch {
        failed.push(client.clientId);
      }
    }));

    return { delivered, failed };
  }
}
