import { Db } from 'mongodb';
import { randomBytes, createHash } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { AUTHORIZATION_REQUEST_COLLECTION, CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { AuthorizationRequestRecord } from '../../oauth/models/authorizationRequest.model';
import { CredentialRecord, isUsable } from '../../directory/models/credential.model';
import { ClientRecord, scopesOf } from '../../oauth/models/client.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { DirectoryService } from '../../directory/services/directory.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { credentialStores } from '../../../shared/ports';
import { newMeta } from '../../../shared/models/base.model';

/**
 * Backchannel authentication: a client asks, and the person approves somewhere else entirely.
 *
 * The approving device signs a challenge this service chose, and that signature IS the
 * authentication. There is no password anywhere in the flow and no browser redirect, which is what
 * makes it usable from a terminal, a call centre or a device with no screen worth typing into.
 *
 * It is deliberately not a parallel pipeline. The pending request is an `authorizationRequest` like
 * an authorization code, the proof goes through the same credential store a passwordless sign-in
 * uses, and the tokens come from the same issuer. The one-pipeline rule is what keeps the audit
 * trail complete: a second implementation is how one of the two ends up without one.
 */

export const BACKCHANNEL_GRANT = 'urn:openid:params:grant-type:ciba';

const DEFAULT_LIFETIME_SECONDS = 300;
const MIN_LIFETIME_SECONDS = 60;
const MAX_LIFETIME_SECONDS = 600;
const POLL_INTERVAL_SECONDS = 5;

export interface BackchannelFailure {
  status: number;
  error: string;
  description?: string;
}

export function isFailure(value: unknown): value is BackchannelFailure {
  return typeof value === 'object' && value !== null && 'error' in value && 'status' in value;
}

function refuse(status: number, error: string, description?: string): BackchannelFailure {
  return { status, error, description };
}

export interface InitiateInput {
  loginHint?: string;
  loginHintToken?: string;
  idTokenHint?: string;
  scope?: string;
  bindingMessage?: string;
  requestedExpiry?: number;
  clientNotificationToken?: string;
}

export interface ChallengeView {
  auth_req_id: string;
  challenge: string;
  binding_message?: string;
  client_id: string;
  client_name: string;
  scopes: string[];
  status: string;
}

export class BackchannelService {
  constructor(private readonly db: Db) {}

  private get requests() {
    return this.db.collection<AuthorizationRequestRecord>(AUTHORIZATION_REQUEST_COLLECTION);
  }

  private audit(realm: RealmRecord, input: {
    action: string;
    outcome: 'success' | 'failure';
    subjectId?: string;
    clientId: string;
    cause?: string;
    detail?: Record<string, unknown>;
  }): void {
    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authentication',
      ...input,
    });
  }

  /**
   * Resolves who is being asked to approve.
   *
   * Exactly one hint, because accepting several and picking one silently makes the choice
   * unauditable: the record would not say which of them identified the person.
   */
  async resolveHint(realmId: string, input: InitiateInput): Promise<string | BackchannelFailure> {
    const present = [input.loginHint, input.loginHintToken, input.idTokenHint].filter(Boolean);
    if (present.length === 0) return refuse(400, 'invalid_request', 'a login hint is required');
    if (present.length > 1) return refuse(400, 'invalid_request', 'provide exactly one login hint');

    const directory = new DirectoryService(this.db);

    if (input.loginHint) {
      const hint = input.loginHint.trim();
      /**
       * A login hint is an email, a user name, or a subject identifier.
       *
       * The subject is the important one and was missing. A client that already knows WHO it wants to
       * ask, because it holds a subject from a previous token, would otherwise have to go back to an
       * email to start a backchannel request, which is the opposite of the direction this flow is
       * meant to travel: the point of the hint token is that a client never handles an address.
       */
      const identity = await directory.findByLogin(realmId, hint)
        ?? await directory.findBySubjectId(hint);

      // The specification's own code for this, and it does disclose whether a hint matched. That is
      // inherent to the flow: a client that cannot learn the hint was wrong cannot ask at all.
      if (!identity || identity.realmId !== realmId) {
        return refuse(400, 'unknown_user_id', 'no principal matches the hint');
      }
      return identity.subjectId;
    }

    // A hint token carries the subject rather than the person's identifiers, which is the point of
    // preferring it: the client never handles an email to start the flow. It is a hint and nothing
    // more, and the person still has to approve, so it is read rather than trusted as authentication.
    const token = (input.loginHintToken ?? input.idTokenHint) as string;
    let subjectId: string | undefined;
    try {
      const segments = token.split('.');
      const payload = JSON.parse(Buffer.from(segments.length >= 2 ? segments[1] : segments[0], 'base64url').toString());
      subjectId = payload.sub;
    } catch {
      return refuse(400, 'invalid_request', 'malformed hint token');
    }
    if (!subjectId) return refuse(400, 'invalid_request', 'hint token carries no subject');

    const identity = await directory.findBySubjectId(subjectId);
    if (!identity || identity.realmId !== realmId) return refuse(400, 'unknown_user_id', 'no principal matches the hint');
    return identity.subjectId;
  }

  async initiate(
    realm: RealmRecord,
    client: ClientRecord,
    input: InitiateInput,
  ): Promise<{ auth_req_id: string; expires_in: number; interval: number } | BackchannelFailure> {
    const mode = client.backchannel?.deliveryMode ?? 'poll';
    if ((mode === 'ping' || mode === 'push') && !input.clientNotificationToken) {
      return refuse(400, 'invalid_request', 'client_notification_token is required for ping and push delivery');
    }

    const allowed = scopesOf(client);
    const requested = (input.scope ?? 'openid').split(' ').filter(Boolean);
    const granted = requested.filter((scope) => allowed.includes(scope));
    if (granted.length === 0) return refuse(400, 'invalid_scope', 'no requested scope is permitted for this client');

    const subjectId = await this.resolveHint(realm.realmId, input);
    if (isFailure(subjectId)) return subjectId;

    // Without a registered key there is nothing that can approve, so the flow is refused now rather
    // than left pending until it expires with no explanation.
    const approvable = await this.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION)
      .findOne({ subjectId, type: 'public_key', status: 'active' }, { projection: { _id: 0 } });
    if (!approvable) return refuse(400, 'unknown_user_id', 'the principal has no active authenticator');

    const lifetime = Math.min(Math.max(input.requestedExpiry ?? DEFAULT_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS), MAX_LIFETIME_SECONDS);
    const authReqId = uuidv4();
    await this.requests.insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      requestId: `req-${authReqId}`,
      flow: 'ciba',
      clientId: client.clientId,
      subjectId,
      status: 'pending',
      scope: granted.join(' '),
      authReqId,
      challenge: randomBytes(32).toString('base64url'),
      ...(input.bindingMessage ? { bindingMessage: input.bindingMessage } : {}),
      ...(input.loginHint ? { loginHint: input.loginHint } : {}),
      ...(input.clientNotificationToken ? { clientNotificationToken: input.clientNotificationToken } : {}),
      interval: POLL_INTERVAL_SECONDS,
      attemptCount: 0,
      expiresAt: new Date(Date.now() + lifetime * 1000).toISOString(),
      meta: newMeta('AuthorizationRequest'),
    } as AuthorizationRequestRecord);

    this.audit(realm, {
      action: 'authentication.backchannel.initiated',
      outcome: 'success',
      subjectId,
      clientId: client.clientId,
      detail: { authReqId, scope: granted, deliveryMode: mode },
    });

    return { auth_req_id: authReqId, expires_in: lifetime, interval: POLL_INTERVAL_SECONDS };
  }

  /** Loads a request, expiring it in passing so a stale one is never presented as live. */
  private async active(realmId: string, authReqId: string): Promise<AuthorizationRequestRecord | BackchannelFailure> {
    const request = await this.requests.findOne({ realmId, authReqId }, { projection: { _id: 0 } });
    if (!request) return refuse(404, 'invalid_grant', 'unknown auth_req_id');
    if (request.status === 'pending' && Date.parse(request.expiresAt) < Date.now()) {
      await this.requests.updateOne({ realmId, authReqId }, { $set: { status: 'expired' } });
      return refuse(400, 'expired_token', 'the request has expired');
    }
    return request;
  }

  async challenge(realmId: string, authReqId: string, clientName: (clientId: string) => Promise<string>): Promise<ChallengeView | BackchannelFailure> {
    const request = await this.active(realmId, authReqId);
    if (isFailure(request)) return request;
    return {
      auth_req_id: request.authReqId as string,
      challenge: request.challenge as string,
      ...(request.bindingMessage ? { binding_message: request.bindingMessage } : {}),
      client_id: request.clientId,
      client_name: await clientName(request.clientId),
      scopes: request.scope.split(' ').filter(Boolean),
      status: request.status,
    };
  }

  async pending(realmId: string, subjectId: string): Promise<ChallengeView[]> {
    const rows = await this.requests
      .find({ realmId, subjectId, flow: 'ciba', status: 'pending' }, { projection: { _id: 0 } })
      .sort({ 'meta.created': -1 })
      .toArray();
    return rows
      .filter((request) => Date.parse(request.expiresAt) > Date.now())
      .map((request) => ({
        auth_req_id: request.authReqId as string,
        challenge: request.challenge as string,
        ...(request.bindingMessage ? { binding_message: request.bindingMessage } : {}),
        client_id: request.clientId,
        client_name: request.clientId,
        scopes: request.scope.split(' ').filter(Boolean),
        status: request.status,
      }));
  }

  /**
   * The approval. A signature over the challenge, checked through the same store a passwordless
   * sign-in uses, so the two cannot drift apart in what they accept.
   */
  async approve(
    realm: RealmRecord,
    authReqId: string,
    input: { credentialId: string; signature: string },
  ): Promise<{ status: 'approved'; clientId: string } | BackchannelFailure> {
    const request = await this.active(realm.realmId, authReqId);
    if (isFailure(request)) return request;

    const rejected = (cause: string) => {
      this.audit(realm, {
        action: 'authentication.backchannel.approve',
        outcome: 'failure',
        subjectId: request.subjectId,
        clientId: request.clientId,
        cause,
        detail: { authReqId },
      });
      return refuse(401, 'invalid_grant', 'the approval could not be verified');
    };

    const credential = await this.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION)
      .findOne({ credentialId: input.credentialId, status: 'active' }, { projection: { _id: 0 } });
    if (!credential || !isUsable(credential)) return rejected('credential_not_found');
    // The authenticator must belong to the person the request named, or a valid signature from any
    // enrolled device would approve any request.
    if (credential.subjectId !== request.subjectId) return rejected('owner_mismatch');

    const store = credentialStores.resolve('public-key');
    const verified = await store.verify(credential.credentialId, `${request.challenge}.${input.signature}`);
    if (!verified) return rejected('bad_signature');

    // Only a still-pending request may be approved, and the transition is the claim. An already
    // handled request cannot be replayed to move the counter or to re-approve.
    const claimed = await this.requests.updateOne(
      { realmId: realm.realmId, authReqId, status: 'pending' },
      { $set: { status: 'approved', 'meta.lastModified': new Date().toISOString() } },
    );
    if (claimed.matchedCount === 0) return rejected('not_pending');

    this.audit(realm, {
      action: 'authentication.backchannel.approve',
      outcome: 'success',
      subjectId: request.subjectId,
      clientId: request.clientId,
      detail: { authReqId, credentialId: credential.credentialId },
    });
    return { status: 'approved', clientId: request.clientId };
  }

  /**
   * The refusal, which needs authorising too.
   *
   * Holding the identifier is not enough: if it were, anyone who saw one in a log could cancel other
   * people's sign-ins. A denial takes the same proof an approval takes, or the owner's own session.
   */
  async deny(
    realm: RealmRecord,
    authReqId: string,
    input: { credentialId?: string; signature?: string; sessionSubjectId?: string },
  ): Promise<{ status: 'denied' } | BackchannelFailure> {
    const request = await this.active(realm.realmId, authReqId);
    if (isFailure(request)) return request;

    let authorized = Boolean(input.sessionSubjectId && input.sessionSubjectId === request.subjectId);
    if (!authorized && input.credentialId && input.signature) {
      const credential = await this.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION)
        .findOne({ credentialId: input.credentialId, status: 'active' }, { projection: { _id: 0 } });
      if (credential && credential.subjectId === request.subjectId) {
        const store = credentialStores.resolve('public-key');
        authorized = await store.verify(credential.credentialId, `${request.challenge}.${input.signature}`);
      }
    }
    if (!authorized) return refuse(401, 'invalid_grant', 'a denial requires the owner proof');

    const claimed = await this.requests.updateOne(
      { realmId: realm.realmId, authReqId, status: 'pending' },
      { $set: { status: 'denied', 'meta.lastModified': new Date().toISOString() } },
    );
    if (claimed.matchedCount === 0) return refuse(400, 'invalid_grant', 'the request is no longer pending');

    this.audit(realm, {
      action: 'authentication.backchannel.deny',
      outcome: 'success',
      subjectId: request.subjectId,
      clientId: request.clientId,
      detail: { authReqId },
    });
    return { status: 'denied' };
  }

  /**
   * Claims an approved request for redemption at the token endpoint.
   *
   * The claim is the state transition, done before anything is minted, so two concurrent polls
   * cannot each produce a token set from one approval.
   */
  async claimApproved(
    realm: RealmRecord,
    clientId: string,
    authReqId: string,
  ): Promise<AuthorizationRequestRecord | BackchannelFailure> {
    if (!authReqId) return refuse(400, 'invalid_request', 'auth_req_id is required');
    const request = await this.requests.findOne({ realmId: realm.realmId, authReqId }, { projection: { _id: 0 } });
    // Unknown and foreign are the same answer: which of the two it was is not the caller's business.
    if (!request || request.clientId !== clientId) return refuse(400, 'invalid_grant', 'unknown auth_req_id');

    if (request.status === 'consumed') return refuse(400, 'invalid_grant', 'already redeemed');
    if (request.status === 'denied') return refuse(400, 'access_denied', 'the request was denied');
    if (request.status === 'expired' || Date.parse(request.expiresAt) < Date.now()) {
      await this.requests.updateOne({ realmId: realm.realmId, authReqId }, { $set: { status: 'expired' } });
      return refuse(400, 'expired_token', 'the request has expired');
    }

    if (request.status === 'pending') {
      const now = Date.now();
      const last = request.meta.lastModified ? Date.parse(request.meta.lastModified) : 0;
      await this.requests.updateOne(
        { realmId: realm.realmId, authReqId },
        { $set: { 'meta.lastModified': new Date().toISOString() }, $inc: { attemptCount: 1 } },
      );
      const interval = (request.interval ?? POLL_INTERVAL_SECONDS) * 1000;
      if (now - last < interval) return refuse(400, 'slow_down', 'polling faster than the stated interval');
      return refuse(400, 'authorization_pending', 'the principal has not approved yet');
    }

    const claimed = await this.requests.updateOne(
      { realmId: realm.realmId, authReqId, status: 'approved' },
      { $set: { status: 'consumed', 'meta.lastModified': new Date().toISOString() } },
    );
    if (claimed.matchedCount === 0) return refuse(400, 'invalid_grant', 'already redeemed');
    return request;
  }

  /**
   * Ping and push delivery.
   *
   * Fire and forget on purpose: a client whose endpoint is down must not turn a completed approval
   * into a failed one. The poll path remains available and is the baseline every client supports.
   */
  async notify(client: ClientRecord, authReqId: string, tokens?: Record<string, unknown>): Promise<void> {
    const endpoint = client.backchannel?.notificationEndpoint;
    const request = await this.requests.findOne({ authReqId }, { projection: { _id: 0 } });
    const notificationToken = request?.clientNotificationToken;
    if (!endpoint || !notificationToken) return;

    const body = JSON.stringify({ auth_req_id: authReqId, ...(tokens ?? {}) });
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          // The notification token authenticates the callback, per the specification, and the
          // signature lets the receiver check the body was not altered on the way.
          authorization: `Bearer ${notificationToken}`,
          'x-signature': createHash('sha256').update(`${notificationToken}.${body}`).digest('hex'),
        },
        body,
        signal: AbortSignal.timeout(3000),
      });
    } catch {
      // See above.
    }
  }
}
