import { FastifyInstance } from 'fastify';
import { createHash, timingSafeEqual } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, readClientCredentials } from '../services/clientAuth.service';
import { TokenIssuer } from '../services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { DirectoryService } from '../../directory/services/directory.service';
import { AUTHORIZATION_REQUEST_COLLECTION } from '../../../shared/models/collections';
import { AuthorizationRequestRecord, isRedeemable } from '../models/authorizationRequest.model';
import { scopesOf } from '../models/client.model';
import { DecisionService } from '../../authorization/services/decision.service';
import { BackchannelService, isFailure, BACKCHANNEL_GRANT } from '../../authentication/services/backchannel.service';
import { TokenExchangeService, isRefusal, TOKEN_EXCHANGE_GRANT } from '../services/tokenExchange.service';
import { DelegationExchangeService, isDelegationRefusal } from '../services/delegationExchange.service';
import { JwtTokenFormat } from '../services/jwtTokenFormat';

/**
 * The token endpoint, RFC 6749.
 *
 * Form encoded, the specification's own error object, and every refusal is `invalid_grant` or
 * `invalid_client` rather than something descriptive: a token endpoint that explains precisely why a
 * grant failed is an oracle, and the caller cannot act on the difference anyway.
 */
export async function tokenController(fastify: FastifyInstance) {
  const ring = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  function fail(reply: never | { status: (code: number) => { send: (body: unknown) => unknown } }, status: number, error: string, description?: string) {
    return reply.status(status).send({ error, ...(description ? { error_description: description } : {}) });
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

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm || !realm.enabled) return fail(reply as never, 400, 'invalid_request', 'unknown realm');

    const clientAuth = new ClientAuthService(fastify.db);
    const presented = readClientCredentials(request.headers.authorization, body);

    // Every grant except the authorization code with a public client requires the client to
    // authenticate. The code grant is handled below, where PKCE stands in for the secret.
    const outcome = await clientAuth.authenticate(realm.realmId, presented, {
      requireAuthentication: grantType !== 'authorization_code',
    });
    if ('error' in outcome) return fail(reply as never, 401, outcome.error, outcome.description);
    const { client } = outcome;

    if (!clientAuth.allowsGrant(client, grantType)) {
      return fail(reply as never, 400, 'unauthorized_client', 'this client is not registered for that grant');
    }

    const issuer = new TokenIssuer(fastify.db, ring());

    if (grantType === 'client_credentials') {
      // No user is involved, so no refresh token and no id token: there is no session to refresh and
      // nobody to describe. A refresh token here would be a longer-lived copy of a credential the
      // client already holds.
      const requested = String(body.scope ?? '').split(' ').filter(Boolean);
      const allowed = scopesOf(client);
      const invalid = requested.filter((scope) => !allowed.includes(scope));
      if (invalid.length > 0) return fail(reply as never, 400, 'invalid_scope', `not permitted: ${invalid.join(' ')}`);

      // A machine principal's permissions are resolved exactly as a person's are, from the roles
      // assigned to it. That is the one-pipeline rule at the authorization step: a service identity
      // is not a special case that skips the decision point.
      const machine = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, client.clientId, client.clientId);

      return reply.send(await issuer.issue({
        realm,
        client,
        subjectId: client.clientId,
        scope: requested.length > 0 ? requested : allowed,
        permissions: machine.permissions,
        roles: machine.roles,
      }));
    }

    if (grantType === 'refresh_token') {
      const presentedToken = String(body.refresh_token ?? '');
      const record = await issuer.findRefreshToken(realm.realmId, presentedToken);
      if (!record || record.clientId !== client.clientId) {
        return fail(reply as never, 400, 'invalid_grant', 'unknown refresh token');
      }
      if (record.revokedAt || Date.parse(record.expiresAt) < Date.now()) {
        return fail(reply as never, 400, 'invalid_grant', 'refresh token is no longer valid');
      }

      // Rotation: the presented token is retired as it is redeemed, so a stolen copy is usable at
      // most once and its use is detectable afterwards.
      await issuer.revoke(realm.realmId, record.jti, 'rotated');

      const directory = new DirectoryService(fastify.db);
      const identity = record.subjectId ? await directory.findBySubjectId(record.subjectId) : null;
      if (record.subjectId && !identity) {
        return fail(reply as never, 400, 'invalid_grant', 'subject no longer exists');
      }

      return reply.send(await issuer.issue({
        realm,
        client,
        subjectId: record.subjectId,
        scope: record.scope.split(' ').filter(Boolean),
        sessionId: record.sessionId,
        sessionEpoch: identity?.sessionEpoch,
        includeRefreshToken: true,
      }));
    }

    if (grantType === 'authorization_code') {
      const code = String(body.code ?? '');
      if (!code) return fail(reply as never, 400, 'invalid_grant', 'code is required');

      const codeHash = createHash('sha256').update(code).digest('hex');
      const requests = fastify.db.collection<AuthorizationRequestRecord>(AUTHORIZATION_REQUEST_COLLECTION);
      const pending = await requests.findOne({ realmId: realm.realmId, codeHash }, { projection: { _id: 0 } });

      if (!pending || pending.clientId !== client.clientId) {
        return fail(reply as never, 400, 'invalid_grant', 'unknown code');
      }
      if (pending.status === 'consumed') {
        // A replay, and it is DETECTED rather than merely absent. Everything issued from the
        // original redemption is revoked, because a code arriving twice means one of the two
        // presenters is not the client.
        if (pending.subjectId) {
          await issuer.revokeSession(realm.realmId, pending.requestId, 'code_replayed');
        }
        return fail(reply as never, 400, 'invalid_grant', 'code has already been used');
      }
      if (!isRedeemable(pending)) return fail(reply as never, 400, 'invalid_grant', 'code is expired');

      if (pending.redirectUri && pending.redirectUri !== String(body.redirect_uri ?? '')) {
        return fail(reply as never, 400, 'invalid_grant', 'redirect_uri does not match');
      }

      if (pending.pkce) {
        const verifier = String(body.code_verifier ?? '');
        if (!verifier) return fail(reply as never, 400, 'invalid_grant', 'code_verifier is required');
        const computed = pending.pkce.method === 'S256'
          ? createHash('sha256').update(verifier).digest('base64url')
          : verifier;
        const a = Buffer.from(computed);
        const b = Buffer.from(pending.pkce.challenge);
        if (a.length !== b.length || !timingSafeEqual(a, b)) {
          return fail(reply as never, 400, 'invalid_grant', 'code_verifier does not match');
        }
      } else if (client.requirePkce) {
        return fail(reply as never, 400, 'invalid_grant', 'this client requires PKCE');
      }

      await requests.updateOne({ requestId: pending.requestId }, { $set: { status: 'consumed' } });

      const directory = new DirectoryService(fastify.db);
      const identity = pending.subjectId ? await directory.findBySubjectId(pending.subjectId) : null;
      if (!identity) return fail(reply as never, 400, 'invalid_grant', 'subject no longer exists');

      const scope = pending.scope.split(' ').filter(Boolean);
      // Resolved at issuance and carried in the token, so a resource server reads a claim rather
      // than calling the authority on every request.
      const decision = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, identity.subjectId, client.clientId);

      return reply.send(await issuer.issue({
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
      }));
    }

    if (grantType === BACKCHANNEL_GRANT) {
      // The approval already happened on the person's own device. What is left is to claim it and
      // mint, through exactly the same issuer the redirect flow uses.
      const backchannel = new BackchannelService(fastify.db);
      const claimed = await backchannel.claimApproved(realm, client.clientId, String(body.auth_req_id ?? ''));
      if (isFailure(claimed)) return fail(reply as never, claimed.status, claimed.error, claimed.description);

      const directory = new DirectoryService(fastify.db);
      const identity = claimed.subjectId ? await directory.findBySubjectId(claimed.subjectId) : null;
      if (!identity) return fail(reply as never, 400, 'invalid_grant', 'subject no longer exists');

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
          return fail(reply as never, 400, 'invalid_grant', 'the subject token did not verify');
        }

        const hop = await new DelegationExchangeService(fastify.db).authorizeHop(realm, client, {
          subjectId: inbound.sub,
          scope: typeof inbound.scope === 'string' ? inbound.scope.split(' ').filter(Boolean) : [],
          actor: inbound.act as never,
        }, {
          scope: String(body.scope ?? '').split(' ').filter(Boolean),
          ...(body.transaction_id ? { transactionId: String(body.transaction_id) } : {}),
        });
        if (isDelegationRefusal(hop)) return fail(reply as never, hop.status, hop.error, hop.description);

        const delegated = await new DecisionService(fastify.db)
          .effectivePermissions(realm.realmId, hop.subjectId, client.clientId);

        return reply.send(await issuer.issue({
          realm,
          client,
          subjectId: hop.subjectId,
          scope: hop.scope,
          permissions: delegated.permissions,
          roles: delegated.roles,
          actor: hop.actor,
          // A delegated token that can renew itself outlives the delegation that produced it.
          includeRefreshToken: false,
        }));
      }

      const exchange = await new TokenExchangeService(fastify.db).resolve(realm, client, {
        subjectToken: String(body.subject_token ?? ''),
        subjectTokenType: body.subject_token_type ? String(body.subject_token_type) : undefined,
        subject: String(body.requested_subject ?? body.audience ?? ''),
      });
      if (isRefusal(exchange)) return fail(reply as never, exchange.status, exchange.error, exchange.description);

      const { identity, actor } = exchange;
      // The permissions are the SUBJECT's, not the caller's. An exchange lets a client act as
      // somebody; it does not let it act as somebody with its own reach added.
      const decision = await new DecisionService(fastify.db)
        .effectivePermissions(realm.realmId, identity.subjectId, client.clientId);
      const scope = String(body.scope ?? '').split(' ').filter(Boolean);

      return reply.send(await issuer.issue({
        realm,
        client,
        subjectId: identity.subjectId,
        scope: scope.length > 0 ? scope : scopesOf(client),
        permissions: decision.permissions,
        roles: decision.roles,
        ...(identity.accountHolderRef ? { accountHolderRef: identity.accountHolderRef } : {}),
        sessionEpoch: identity.sessionEpoch,
        actor,
        // No refresh token. A delegated token that can renew itself outlives the reason it was
        // granted, and this one exists for the length of one demonstration.
        includeRefreshToken: false,
      }));
    }

    return fail(reply as never, 400, 'unsupported_grant_type', `grant_type ${grantType} is not supported`);
  });
}
