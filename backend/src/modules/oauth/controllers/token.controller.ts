import { FastifyInstance } from 'fastify';
import { createHash, timingSafeEqual } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, readClientCredentials, recordSoftAdmission } from '../services/clientAuth.service';
import { TokenIssuer } from '../services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { DirectoryService } from '../../directory/services/directory.service';
import { AUTH_REQUEST_COLLECTION } from '../../../shared/models/collections';
import { AuthRequestRecord, isRedeemable } from '../models/authRequest.model';
import { scopesOf, OAuthClient } from '../models/client.model';
import { DecisionService } from '../../authorization/services/decision.service';
import { BackchannelService, isFailure, BACKCHANNEL_GRANT } from '../../authentication/services/backchannel.service';
import { TokenExchangeService, isRefusal, TOKEN_EXCHANGE_GRANT } from '../services/tokenExchange.service';
import { DelegationExchangeService, isDelegationRefusal } from '../services/delegationExchange.service';
import { JwtTokenFormat } from '../services/jwtTokenFormat';
import { SecurityEventService, classifyFailure, hashIp, hashState } from '../../audit/services/securityEvent.service';
import { GrantService } from '../../consent/services/grant.service';
import { RealmRecord } from '../../realm/models/realm.model';

/**
 * The token endpoint, RFC 6749.
 *
 * Form encoded, the specification's own error object, and every refusal is `invalid_grant` or
 * `invalid_client` rather than something descriptive: a token endpoint that explains precisely why a
 * grant failed is an oracle, and the caller cannot act on the difference anyway.
 *
 * Every issuance and every refusal is recorded against the subject the token is FOR, never against
 * the client that asked. That field choice is what lets a person read their own trail and answer
 * "what has this application been doing with my account", which an administrator-only record cannot.
 */
export async function tokenController(fastify: FastifyInstance) {
  const ring = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  function fail(reply: never | { status: (code: number) => { send: (body: unknown) => unknown } }, status: number, error: string, description?: string) {
    return reply.status(status).send({ error, ...(description ? { error_description: description } : {}) });
  }

  /**
   * One issuance, recorded.
   *
   * `onBehalf` separates the two cases a reader has to tell apart: the person drove the flow
   * themselves, or an application obtained a token for them. When an application acted, the principal
   * and the acting agent are named in their own fields rather than collapsed into one subject.
   */
  function recordIssued(
    realm: RealmRecord,
    input: {
      grantType: string;
      client: OAuthClient;
      subjectId?: string;
      scope: string[];
      onBehalf?: boolean;
      correlationId: string;
      ipHash?: string;
      transactionId?: string;
      delegationId?: string;
    },
  ) {
    const forPerson = Boolean(input.subjectId) && input.subjectId !== input.client.clientId;
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'token',
      action: 'token.issued',
      outcome: 'success',
      clientId: input.client.clientId,
      ...(input.subjectId ? { subjectId: input.subjectId } : {}),
      correlationId: input.correlationId,
      ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      ...(input.onBehalf && forPerson ? { principalSubjectId: input.subjectId, agentId: input.client.clientId } : {}),
      ...(input.transactionId ? { transactionId: input.transactionId } : {}),
      ...(input.delegationId ? { delegationId: input.delegationId } : {}),
      detail: {
        grantType: input.grantType,
        clientName: input.client.clientName,
        scope: input.scope,
        // The plain-language distinction the trail exists to answer.
        actedFor: !forPerson ? 'itself' : input.onBehalf ? 'the principal' : 'the signed-in person',
      },
    });
  }

  fastify.post('/realms/:realm/protocol/openid-connect/token', {
    schema: {
      operationId: 'issueToken',
      tags: ['oauth'],
      summary: 'Token endpoint',
      description:
        'Standard-defined: RFC 6749 sections 4.1.3, 4.4 and 6, with PKCE per RFC 7636 and the access '
        + 'token in the RFC 9068 JWT profile. Requests are `application/x-www-form-urlencoded` and '
        + 'errors use the RFC 6749 section 5.2 object, never a house envelope. Client authentication '
        + 'is HTTP Basic or the form body, per RFC 6749 section 2.3.',
      security: [{ clientBasic: [] }, {}],
      consumes: ['application/x-www-form-urlencoded'],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['grant_type'],
        additionalProperties: true,
        properties: {
          grant_type: {
            type: 'string',
            description: 'authorization_code, client_credentials, refresh_token or the backchannel grant.',
            examples: ['client_credentials'],
          },
          code: { type: 'string' },
          auth_req_id: { type: 'string', description: 'The backchannel grant: the request the principal approved.' },
          subject_token: { type: 'string', description: 'Token exchange, RFC 8693: the token being exchanged.' },
          subject_token_type: { type: 'string' },
          requested_subject: { type: 'string', description: 'Token exchange: impersonate this principal. Omit it for a DELEGATED hop, which is the default and keeps the acting party visible.' },
          transaction_id: { type: 'string', description: 'Binds a delegated token to one task, where the delegation requires it.' },
          redirect_uri: { type: 'string' },
          code_verifier: { type: 'string' },
          refresh_token: { type: 'string' },
          scope: { type: 'string' },
          client_id: { type: 'string' },
          client_secret: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'The issued tokens.',
          type: 'object',
          additionalProperties: true,
          required: ['access_token', 'token_type', 'expires_in'],
          properties: {
            access_token: { type: 'string' },
            token_type: { type: 'string' },
            expires_in: { type: 'integer' },
            scope: { type: 'string' },
            refresh_token: { type: 'string' },
            id_token: { type: 'string' },
          },
          examples: [{ access_token: 'eyJ…', token_type: 'Bearer', expires_in: 900, scope: 'openid profile' }],
        },
        400: { $ref: 'OAuthError#', description: 'The grant is invalid or unsupported.' },
        401: { $ref: 'OAuthError#', description: 'Client authentication failed.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = (request.body ?? {}) as Record<string, unknown>;
    const grantType = String(body.grant_type ?? '');

    // The request's own correlator until a redemption can be tied to the authorization that produced
    // it, at which point it becomes the flow's. Reassignable for exactly that reason.
    let correlationId = request.correlationId;
    const ipHash = hashIp(request.ip);

    const realm = await new RealmService(fastify.db).byName(realmName);
    // Not recorded: with no realm there is no trail to record it in, and no subject it concerns.
    if (!realm || !realm.enabled) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    // What is known about the request so far, so a refusal names the client and the subject it was
    // about. A failure recorded against nobody is a failure the person concerned cannot see.
    const context: { clientId?: string; clientName?: string; subjectId?: string } = {};

    /** Refuses and records. Repeated refusals for one account are themselves worth seeing. */
    const refuse = (status: number, error: string, description?: string) => {
      void new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'token',
        action: 'token.issued',
        outcome: 'failure',
        cause: classifyFailure(error, description),
        correlationId,
        ...(ipHash ? { ipHash } : {}),
        ...(context.clientId ? { clientId: context.clientId } : {}),
        ...(context.subjectId ? { subjectId: context.subjectId } : {}),
        detail: {
          grantType,
          ...(context.clientName ? { clientName: context.clientName } : {}),
        },
      });
      return fail(reply as never, status, error, description);
    };

    const clientAuth = new ClientAuthService(fastify.db);
    const presented = readClientCredentials(request.headers.authorization, body);
    // Named from what was presented, so a client that fails to authenticate is still identified.
    context.clientId = presented.clientId;

    // Every grant except the authorization code with a public client requires the client to
    // authenticate. The code grant is handled below, where PKCE stands in for the secret.
    const outcome = await clientAuth.authenticate(realm, presented, {
      requireAuthentication: grantType !== 'authorization_code',
      // Soft admission is offered here and refused everywhere privileged. What it relaxes is a
      // consumer that has not registered yet, not a consumer that failed to authenticate.
      allowSoftAdmission: true,
    });
    if ('error' in outcome) return refuse(401, outcome.error, outcome.description);
    const { client, softAdmitted } = outcome;
    context.clientId = client.clientId;
    context.clientName = client.clientName;

    if (!clientAuth.allowsGrant(client, grantType)) {
      return refuse(400, 'unauthorized_client', 'this client is not registered for that grant');
    }

    if (softAdmitted) {
      await recordSoftAdmission(fastify.db, realm, {
        clientId: client.clientId,
        endpoint: 'token',
        address: request.ip,
      });
    }

    const issuer = new TokenIssuer(fastify.db, ring(), { reducedAuthority: softAdmitted });

    if (grantType === 'client_credentials') {
      // No user is involved, so no refresh token and no id token: there is no session to refresh and
      // nobody to describe. A refresh token here would be a longer-lived copy of a credential the
      // client already holds.
      const requested = String(body.scope ?? '').split(' ').filter(Boolean);
      const allowed = scopesOf(client);
      const invalid = requested.filter((scope) => !allowed.includes(scope));
      if (invalid.length > 0) return refuse(400, 'invalid_scope', `not permitted: ${invalid.join(' ')}`);

      /**
       * The `sub` is the principal the registration ACTS AS, and it must be a real one.
       *
       * An application is not a principal here, deliberately: that would make a principal able to
       * own a principal, which is recursive, and every ownership query would have to decide how deep
       * to look. So the grant issues a token whose subject is the OWNING principal, of kind
       * `service` or `workload`. That is better than the alternative rather than a workaround, since
       * a service token is then attributable to a subject with a lifecycle and an owner instead of
       * to an abstract application that answers for nothing.
       *
       * Refused when the owner is neither kind, because a token issued as a person for a machine
       * grant is an attribution nobody could defend afterwards.
       */
      const owner = await new DirectoryService(fastify.db).findBySubjectId(client.clientId);
      if (!owner) {
        return refuse(400, 'invalid_client', 'this registration names no principal to act as');
      }
      if (owner.kind !== 'service' && owner.kind !== 'workload') {
        return refuse(
          400,
          'unauthorized_client',
          'client_credentials issues a token as the owning principal, which must be a service or a workload',
        );
      }

      // A machine principal's permissions are resolved exactly as a person's are, from the roles
      // it holds. That is the one-pipeline rule at the authorization step: a service identity is not
      // a special case that skips the decision point.
      const machine = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, owner.subjectId, client.clientId);

      const scope = requested.length > 0 ? requested : allowed;
      const tokens = await issuer.issue({
        realm,
        client,
        subjectId: owner.subjectId,
        scope,
        permissions: machine.permissions,
        roles: machine.roles,
      });
      recordIssued(realm, { grantType, client, subjectId: owner.subjectId, scope, correlationId, ipHash });
      return reply.send(tokens);
    }

    if (grantType === 'refresh_token') {
      const presentedToken = String(body.refresh_token ?? '');

      /**
       * Rotation with reuse detection, against one integer on the session.
       *
       * Redemption verifies the token, compares its generation against the session's, and increments
       * atomically. Nothing is looked up in a token collection, because no token was ever stored.
       */
      const redeemed = await issuer.redeemRefresh(realm.realmId, presentedToken);
      // Named before the refusal is written, so it is recorded against the account it concerns.
      context.subjectId = redeemed.subjectId;

      if (!redeemed.ok) {
        if (redeemed.cause === 'reuse_detected') {
          /**
           * A token that had already been rotated was presented again.
           *
           * The legitimate holder cannot do this: they hold the token they were last given. So the
           * assumption is theft, the WHOLE SESSION has been deleted, and this is recorded as its own
           * event rather than as an ordinary invalid_grant. Refusing only this one token would have
           * left the next attempt equally cheap.
           */
          await new SecurityEventService(fastify.db).record({
            realmId: realm.realmId,
            tenantId: realm.tenantId,
            category: 'token',
            action: 'oauth.refresh.reuse_detected',
            outcome: 'failure',
            cause: 'refresh_token_replayed',
            clientId: client.clientId,
            ...(redeemed.subjectId ? { subjectId: redeemed.subjectId } : {}),
            ...(redeemed.subjectId ? { stakeholderSubjectIds: [redeemed.subjectId] } : {}),
            ...(redeemed.sessionId ? { target: { type: 'session', ref: redeemed.sessionId } } : {}),
            correlationId,
            ...(ipHash ? { ipHash } : {}),
            detail: {
              outcome: 'session deleted',
              reason:
                'a refresh token that had already been rotated was presented again, so the session '
                + 'is assumed compromised and every access under it ends',
            },
          });
          return refuse(400, 'invalid_grant', 'refresh token has already been used');
        }
        return refuse(400, 'invalid_grant', 'refresh token is no longer valid');
      }

      if (redeemed.clientId !== client.clientId) {
        return refuse(400, 'invalid_grant', 'unknown refresh token');
      }

      const directory = new DirectoryService(fastify.db);
      const identity = redeemed.subjectId ? await directory.findBySubjectId(redeemed.subjectId) : null;
      if (redeemed.subjectId && !identity) {
        return refuse(400, 'invalid_grant', 'subject no longer exists');
      }

      // The scope comes from the grant that established the session rather than from a stored token
      // row, since there is no longer one to read it back from.
      const scope = String(body.scope ?? '').split(' ').filter(Boolean);
      /**
       * Resolved again, exactly as every other grant resolves it.
       *
       * Omitting this was a silent privilege LOSS, not a saving: the permission and role claims are
       * conditional in the issuer, so a refreshed token simply had neither, and every resource server
       * applied its default deny. A person signed in through an application kept working until their
       * first refresh and was then told their role did not permit what it plainly did.
       *
       * Resolving rather than copying from the retired token is also the correct behaviour: a
       * permission withdrawn while a session is live must not survive in a refresh, which is the whole
       * reason access tokens are short.
       */
      const decision = redeemed.subjectId
        ? await new DecisionService(fastify.db)
          .effectivePermissions(realm.realmId, redeemed.subjectId, client.clientId)
        : null;

      const tokens = await issuer.issue({
        realm,
        client,
        subjectId: redeemed.subjectId,
        scope,
        sessionId: redeemed.sessionId,
        sessionEpoch: identity?.sessionEpoch,
        ...(decision ? { permissions: decision.permissions, roles: decision.roles } : {}),
        ...(identity?.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
        includeRefreshToken: true,
      });
      recordIssued(realm, { grantType, client, subjectId: redeemed.subjectId, scope, correlationId, ipHash });
      return reply.send(tokens);
    }

    if (grantType === 'authorization_code') {
      const code = String(body.code ?? '');
      if (!code) return refuse(400, 'invalid_grant', 'code is required');

      const codeHash = createHash('sha256').update(code).digest('hex');
      const requests = fastify.db.collection<AuthRequestRecord>(AUTH_REQUEST_COLLECTION);
      const pending = await requests.findOne({ realmId: realm.realmId, codeHash }, { projection: { _id: 0 } });

      if (!pending || pending.clientId !== client.clientId) {
        return refuse(400, 'invalid_grant', 'unknown code');
      }
      context.subjectId = pending.subjectId;
      // From here the redemption belongs to the authorization that produced the code, so it carries
      // that flow's correlator rather than this request's. Derived, never the state itself.
      if (pending.state) correlationId = hashState(pending.state);
      if (pending.status === 'consumed') {
        // A replay, and it is DETECTED rather than merely absent. Everything issued from the
        // original redemption is revoked, because a code arriving twice means one of the two
        // presenters is not the client.
        if (pending.subjectId) {
          await issuer.revokeSession(realm.realmId, pending.requestId);
        }
        return refuse(400, 'invalid_grant', 'code has already been used');
      }
      if (!isRedeemable(pending)) return refuse(400, 'invalid_grant', 'code is expired');

      if (pending.redirectUri && pending.redirectUri !== String(body.redirect_uri ?? '')) {
        return refuse(400, 'invalid_grant', 'redirect_uri does not match');
      }

      if (pending.pkce) {
        const verifier = String(body.code_verifier ?? '');
        if (!verifier) return refuse(400, 'invalid_grant', 'code_verifier is required');
        const computed = pending.pkce.method === 'S256'
          ? createHash('sha256').update(verifier).digest('base64url')
          : verifier;
        const a = Buffer.from(computed);
        const b = Buffer.from(pending.pkce.challenge);
        if (a.length !== b.length || !timingSafeEqual(a, b)) {
          return refuse(400, 'invalid_grant', 'code_verifier does not match');
        }
      } else if (client.requirePkce) {
        return refuse(400, 'invalid_grant', 'this client requires PKCE');
      }

      await requests.updateOne({ requestId: pending.requestId }, { $set: { status: 'consumed' } });

      const directory = new DirectoryService(fastify.db);
      const identity = pending.subjectId ? await directory.findBySubjectId(pending.subjectId) : null;
      if (!identity) return refuse(400, 'invalid_grant', 'subject no longer exists');

      const scope = pending.scope.split(' ').filter(Boolean);
      // Resolved at issuance and carried in the token, so a resource server reads a claim rather
      // than calling the authority on every request.
      const decision = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, identity.subjectId, client.clientId);

      const tokens = await issuer.issue({
        realm,
        client,
        subjectId: identity.subjectId,
        scope,
        permissions: decision.permissions,
        roles: decision.roles,
        ...(identity.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
        sessionEpoch: identity.sessionEpoch,
        nonce: pending.nonce,
        includeRefreshToken: true,
        includeIdToken: scope.includes('openid'),
        idTokenClaims: {
          name: identity.name?.formatted,
          preferred_username: identity.userName,
          ...(scope.includes('email') && identity.primaryEmail ? { email: identity.primaryEmail } : {}),
        },
      });

      recordIssued(realm, { grantType, client, subjectId: identity.subjectId, scope, correlationId, ipHash });
      // Redeeming a code is the moment the person's approval becomes an ongoing authorisation.
      await new GrantService(fastify.db).consent(realm, identity.subjectId, client, scope);
      return reply.send(tokens);
    }

    if (grantType === BACKCHANNEL_GRANT) {
      // The approval already happened on the person's own device. What is left is to claim it and
      // mint, through exactly the same issuer the redirect flow uses.
      const backchannel = new BackchannelService(fastify.db);
      const claimed = await backchannel.claimApproved(realm, client.clientId, String(body.auth_req_id ?? ''));
      if (isFailure(claimed)) return refuse(claimed.status, claimed.error, claimed.description);

      const directory = new DirectoryService(fastify.db);
      const identity = claimed.subjectId ? await directory.findBySubjectId(claimed.subjectId) : null;
      if (!identity) return refuse(400, 'invalid_grant', 'subject no longer exists');

      const scope = claimed.scope.split(' ').filter(Boolean);
      const decision = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, identity.subjectId, client.clientId);

      const tokens = await issuer.issue({
        realm,
        client,
        subjectId: identity.subjectId,
        scope,
        permissions: decision.permissions,
        roles: decision.roles,
        ...(identity.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
        sessionEpoch: identity.sessionEpoch,
        includeRefreshToken: true,
        includeIdToken: scope.includes('openid'),
        idTokenClaims: {
          name: identity.name?.formatted,
          preferred_username: identity.userName,
          ...(scope.includes('email') && identity.primaryEmail ? { email: identity.primaryEmail } : {}),
        },
      });

      // push delivery carries the tokens to the client's endpoint as well. The poll that got here
      // already claimed the request, so this cannot produce a second set.
      recordIssued(realm, { grantType, client, subjectId: identity.subjectId, scope, correlationId, ipHash });
      // The person approved on their own device, so this is consent in exactly the sense the code
      // grant records it.
      await new GrantService(fastify.db).consent(realm, identity.subjectId, client, scope);

      if (client.backchannel?.deliveryMode === 'push') {
        void backchannel.notify(client, claimed.authReqId as string, tokens as unknown as Record<string, unknown>);
      }
      return reply.send(tokens);
    }

    if (grantType === TOKEN_EXCHANGE_GRANT) {
      /**
       * Delegation is the default; impersonation is the exception and must be asked for.
       *
       * They are not equivalent for accountability. Delegation keeps `sub` as the person and names
       * the acting party in `act`, so both are visible downstream. Impersonation REPLACES the
       * subject, and every system after this point then sees only the person: the agent's part in
       * what happened is gone, and no amount of logging elsewhere reconstructs it.
       *
       * So the caller has to say `requested_subject` to get impersonation, and even that is refused
       * unless the realm and the target both permit it. Anything else is a delegated hop.
       */
      const wantsImpersonation = Boolean(body.requested_subject ?? body.audience);

      if (!wantsImpersonation) {
        const inbound = await new JwtTokenFormat(ring(), realm.realmId)
          .verify(String(body.subject_token ?? ''), { issuer: realm.issuer, audience: client.clientId })
          .catch(() => null);
        // The inbound token is VERIFIED, not merely parsed. A hop that trusted a decoded token would
        // let any caller assert the subject and chain it wanted to continue.
        if (!inbound || typeof inbound.sub !== 'string') {
          return refuse(400, 'invalid_grant', 'the subject token did not verify');
        }

        const hop = await new DelegationExchangeService(fastify.db).authorizeHop(realm, client, {
          subjectId: inbound.sub,
          scope: typeof inbound.scope === 'string' ? inbound.scope.split(' ').filter(Boolean) : [],
          actor: inbound.act as never,
        }, {
          scope: String(body.scope ?? '').split(' ').filter(Boolean),
          ...(body.transaction_id ? { transactionId: String(body.transaction_id) } : {}),
        });
        if (isDelegationRefusal(hop)) return refuse(hop.status, hop.error, hop.description);

        const delegated = await new DecisionService(fastify.db)
          .effectivePermissions(realm.realmId, hop.subjectId, client.clientId);

        const tokens = await issuer.issue({
          realm,
          client,
          subjectId: hop.subjectId,
          scope: hop.scope,
          permissions: delegated.permissions,
          roles: delegated.roles,
          actor: hop.actor,
          // A delegated token that can renew itself outlives the delegation that produced it.
          includeRefreshToken: false,
        });
        recordIssued(realm, {
          grantType,
          client,
          subjectId: hop.subjectId,
          scope: hop.scope,
          // The person did not drive this: an application obtained a token to act for them.
          onBehalf: true,
          correlationId,
          ipHash,
          delegationId: hop.delegation.delegationId,
          ...(body.transaction_id ? { transactionId: String(body.transaction_id) } : {}),
        });
        return reply.send(tokens);
      }

      const exchange = await new TokenExchangeService(fastify.db).resolve(realm, client, {
        subjectToken: String(body.subject_token ?? ''),
        subjectTokenType: body.subject_token_type ? String(body.subject_token_type) : undefined,
        subject: String(body.requested_subject ?? body.audience ?? ''),
      });
      if (isRefusal(exchange)) return refuse(exchange.status, exchange.error, exchange.description);

      const { identity, actor } = exchange;
      // The permissions are the SUBJECT's, not the caller's. An exchange lets a client act as
      // somebody; it does not let it act as somebody with its own reach added.
      const decision = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, identity.subjectId, client.clientId);
      const scope = String(body.scope ?? '').split(' ').filter(Boolean);

      const effective = scope.length > 0 ? scope : scopesOf(client);
      const tokens = await issuer.issue({
        realm,
        client,
        subjectId: identity.subjectId,
        scope: effective,
        permissions: decision.permissions,
        roles: decision.roles,
        ...(identity.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
        sessionEpoch: identity.sessionEpoch,
        actor,
        // No refresh token. A delegated token that can renew itself outlives the reason it was
        // granted, and this one exists for the length of one demonstration.
        includeRefreshToken: false,
      });
      recordIssued(realm, {
        grantType,
        client,
        subjectId: identity.subjectId,
        scope: effective,
        onBehalf: true,
        correlationId,
        ipHash,
      });
      return reply.send(tokens);
    }

    return refuse(400, 'unsupported_grant_type', `grant_type ${grantType} is not supported`);
  });
}
