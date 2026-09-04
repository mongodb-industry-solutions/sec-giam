import { FastifyInstance } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { createHash, randomBytes } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, provisionalClient, recordSoftAdmission } from '../services/clientAuth.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { TICKET_COLLECTION, SESSION_COLLECTION } from '../../../shared/models/collections';
import { TicketRecord } from '../models/ticket.model';
import { SessionRecord, isLive } from '../../authentication/models/session.model';
import { scopesOf } from '../models/client.model';
import { enforcementFor } from '../../realm/models/realm.model';
import { newMeta } from '../../../shared/models/base.model';
import { oauthError } from '../../../shared/models/problem';
import type { OAuthErrorCode } from '../../../shared/models/problem';
import { SecurityEventService, hashIp, hashState } from '../../audit/services/securityEvent.service';
import { GrantService } from '../../consent/services/grant.service';

/**
 * The authorization endpoint, RFC 6749 §4.1 with PKCE.
 *
 * Exchanges an established session for a one-time code. The session is what the sign-in produced;
 * this turns it into something a specific client can redeem exactly once, for a specific redirect,
 * with a specific proof.
 *
 * Deliberately NOT a place that accepts credentials. A client sends a browser here and gets a code
 * back; if there is no session, the answer is that one is needed, never a prompt this endpoint
 * handles itself. Keeping credential entry in one place is the whole reason the authority exists.
 *
 * The mint and every refusal are recorded. A redirect URI that does not match the registration is the
 * signal that somebody is trying to have a code delivered somewhere it does not belong, and a trail
 * that starts at the token endpoint never sees it. The correlator is derived from the state parameter
 * the same way the token endpoint derives it, so one authorization and its redemption read as one
 * flow rather than two unrelated entries.
 */
export async function authorizeController(fastify: FastifyInstance) {
  fastify.post('/realms/:realm/protocol/openid-connect/auth', {
    schema: {
      operationId: 'authorize',
      tags: ['oauth'],
      summary: 'Authorization endpoint',
      description:
        'Standard-defined: RFC 6749 section 4.1 and RFC 7636 (PKCE). Exchanges an established '
        + 'session for a single-use authorization code bound to the client, the redirect URI and the '
        + 'PKCE challenge. It never accepts a credential: a request with no session is told one is '
        + 'required rather than being prompted here.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['client_id', 'redirect_uri', 'response_type', 'session_id'],
        additionalProperties: false,
        properties: {
          client_id: { type: 'string', examples: ['orders-web'] },
          redirect_uri: { type: 'string', examples: ['https://app.example/callback'] },
          response_type: { type: 'string', enum: ['code'] },
          scope: { type: 'string', examples: ['openid profile'] },
          state: { type: 'string' },
          nonce: { type: 'string' },
          code_challenge: { type: 'string' },
          code_challenge_method: { type: 'string', enum: ['S256'] },
          session_id: { type: 'string', description: 'The session established at sign-in.' },
          prompt: {
            type: 'string',
            enum: ['none', 'consent'],
            description: 'OIDC: `consent` asks again even when a grant already covers the request.',
          },
          consent_granted: {
            type: 'boolean',
            description: 'Set by the consent screen when the person approved. Never set by a client.',
          },
        },
      },
      response: {
        200: {
          description:
            'Either the authorization code, or a statement that the person has not yet authorised '
            + 'this application. `code` is absent in the second case and `consent_required` is true; '
            + 'the caller shows the scopes and asks, then repeats the request with consent_granted.',
          type: 'object',
          additionalProperties: false,
          required: ['redirect_uri'],
          properties: {
            code: { type: 'string' },
            state: { type: 'string' },
            redirect_uri: { type: 'string' },
            consent_required: { type: 'boolean' },
            client_name: { type: 'string' },
            client_uri: { type: 'string' },
            logo_uri: { type: 'string' },
            scopes: { type: 'array', items: { type: 'string' } },
          },
          examples: [{ code: 'a1b2…', state: 'xyz', redirect_uri: 'https://app.example/callback' }],
        },
        400: { $ref: 'OAuthError#', description: 'The request is invalid or the scope is not permitted.' },
        401: { $ref: 'OAuthError#', description: 'No live session.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as {
      client_id: string;
      redirect_uri: string;
      response_type: string;
      scope?: string;
      state?: string;
      nonce?: string;
      code_challenge?: string;
      code_challenge_method?: 'S256';
      session_id: string;
      prompt?: 'none' | 'consent';
      consent_granted?: boolean;
    };

    const realm = await new RealmService(fastify.db).byName(realmName);
    // Not recorded: with no realm there is no trail to record it in, which is the token endpoint's
    // position on the same case.
    if (!realm || !realm.enabled) return reply.status(400).send(oauthError('invalid_request', 'unknown realm'));

    // The same correlator the token endpoint derives, so authorize and redemption group together. The
    // state is never stored raw: it is a value the client chose, and the trail only needs to say that
    // two records belong to one flow.
    const correlationId = body.state ? hashState(body.state) : request.correlationId;
    const ipHash = hashIp(request.ip);
    // What is known so far. A refusal names the subject once one is resolved, and the client until
    // then: a failure recorded against nobody is a failure nobody can be shown.
    const context: { subjectId?: string } = {};

    /**
     * Refuses and records.
     *
     * The RFC 6749 error code and the recorded cause are separate arguments, because they answer
     * different questions: the code is what a client switches on, the cause is what an investigator
     * reads. They were conflated and the code was derived from the status, so every refusal here
     * reached the client as `invalid_request` however precisely the cause had been determined.
     */
    const refuse = (status: number, code: OAuthErrorCode, description: string, cause: string) => {
      void new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'token',
        action: 'authorization.code_issued',
        outcome: 'failure',
        cause,
        correlationId,
        clientId: body.client_id,
        ...(context.subjectId ? { subjectId: context.subjectId } : {}),
        ...(ipHash ? { ipHash } : {}),
        detail: { responseType: body.response_type, scope: body.scope },
      });
      return reply.status(status as 400).send(oauthError(code, description, status));
    };

    if (body.response_type !== 'code') {
      return refuse(400, 'unsupported_response_type', 'unsupported response_type', 'unsupported_response_type');
    }

    const registered = await new ClientAuthService(fastify.db).find(realm.realmId, body.client_id);
    if (registered && registered.status !== 'active') {
      return refuse(400, 'unauthorized_client', 'unknown client', 'client_not_active');
    }

    // Soft mode admits a client that has never registered. It does NOT admit one that registered and
    // then presented the wrong redirect: that client is known, so its registration is the answer.
    const softAdmitted = !registered && enforcementFor(realm) === 'soft';
    if (!registered && !softAdmitted) {
      return refuse(400, 'invalid_request', 'unknown client', 'unknown_client');
    }
    // A provisional client has no registered redirect, so the one presented is the one it gets, and
    // it holds the minimum scope rather than whatever it asked for.
    const client = registered ?? provisionalClient(realm, body.client_id, [body.redirect_uri]);

    // Exact match, never a prefix. A redirect URI compared loosely is how an authorization code ends
    // up delivered to an attacker's path on a legitimate host.
    if (!client.redirectUris.includes(body.redirect_uri)) {
      return refuse(400, 'invalid_request', 'redirect_uri is not registered for this client', 'redirect_uri_mismatch');
    }

    if (client.requirePkce && !body.code_challenge) {
      return refuse(400, 'invalid_request', 'this client requires PKCE', 'pkce_missing');
    }
    // A challenge with a method this authority does not implement is worse than none: the client
    // believes it is protected and the redemption would compare the wrong bytes.
    if (body.code_challenge && body.code_challenge_method && body.code_challenge_method !== 'S256') {
      return refuse(400, 'invalid_request', 'unsupported code_challenge_method', 'pkce_method_unsupported');
    }

    if (softAdmitted) {
      await recordSoftAdmission(fastify.db, realm, {
        clientId: client.clientId,
        endpoint: 'authorize',
        address: request.ip,
      });
    }

    const asked = (body.scope ?? 'openid').split(' ').filter(Boolean);
    const permitted = scopesOf(client);
    // Narrowed for a soft admission, refused for a registered client. The two are different cases:
    // narrowing here IS the limit soft mode applies, and the reduction is recorded above and echoed
    // in the token's scope, so the client learns what it actually holds. For a registered client
    // silently dropping a scope would mean it believes it holds authority it does not.
    const requested = softAdmitted ? permitted : asked;
    const refused = softAdmitted ? [] : asked.filter((scope) => !permitted.includes(scope));
    if (refused.length > 0) {
      return refuse(400, 'invalid_scope', `scope not permitted: ${refused.join(' ')}`, 'scope_not_permitted');
    }

    const session = await fastify.db
      .collection<SessionRecord>(SESSION_COLLECTION)
      .findOne({ realmId: realm.realmId, sessionId: body.session_id }, { projection: { _id: 0 } });
    if (!session || !isLive(session)) {
      return refuse(401, 'login_required', 'no live session', 'no_live_session');
    }
    // Named as soon as the session resolves, so anything refused after this point reaches the person
    // it concerned rather than only the application.
    context.subjectId = session.subjectId;

    const identity = await new DirectoryService(fastify.db).findBySubjectId(session.subjectId);
    if (!identity) return refuse(401, 'login_required', 'no live session', 'subject_no_longer_exists');

    /**
     * Has this person agreed to hand their identity to this application?
     *
     * The identities are this authority's, not the applications', so every application asks, and the
     * answer is remembered per client and per scope. `prompt=consent` asks again regardless, which is
     * what lets a person re-read what they granted. Only the authority's own console is exempt.
     *
     * A refusal is not modelled here: the person simply is not sent back with a code, and the console
     * returns `access_denied` to the application on their behalf.
     */
    if (!client.firstParty) {
      const grants = new GrantService(fastify.db);
      const alreadyHeld = body.prompt === 'consent'
        ? false
        : await grants.covers(realm.realmId, identity.subjectId, client.clientId, requested);

      if (!alreadyHeld && !body.consent_granted) {
        return reply.send({
          consent_required: true,
          redirect_uri: body.redirect_uri,
          client_name: client.clientName ?? client.clientId,
          scopes: requested,
          ...(client.clientUri ? { client_uri: client.clientUri } : {}),
          ...(client.logoUri ? { logo_uri: client.logoUri } : {}),
          ...(body.state ? { state: body.state } : {}),
        });
      }
      // Recorded as the person's own approval, which is what populates the list of applications they
      // can later review and withdraw.
      if (!alreadyHeld) {
        await grants.consent(realm, identity.subjectId, client, requested);
      }
    }

    const code = randomBytes(32).toString('base64url');
    const now = new Date();
    const record: TicketRecord = {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      requestId: uuidv4(),
      flow: 'authorization_code',
      clientId: client.clientId,
      subjectId: identity.subjectId,
      status: 'approved',
      // Hashed at rest, for the same reason a password is: reading this collection must not leave
      // anyone able to redeem an outstanding authorization.
      codeHash: createHash('sha256').update(code).digest('hex'),
      ...(body.code_challenge
        ? { pkce: { challenge: body.code_challenge, method: body.code_challenge_method ?? 'S256' } }
        : {}),
      redirectUri: body.redirect_uri,
      ...(body.state ? { state: body.state, stateHash: createHash('sha256').update(body.state).digest('hex').slice(0, 16) } : {}),
      ...(body.nonce ? { nonce: body.nonce } : {}),
      scope: requested.join(' '),
      attemptCount: 0,
      // Short by design: a code is a bearer credential in a URL, and its window should be the time a
      // browser needs to complete one redirect, not the time a person needs to read a page.
      expiresAt: new Date(now.getTime() + realm.tokenPolicy.codeTtlSeconds * 1000).toISOString(),
      meta: newMeta('AuthorizationRequest'),
    };
    await fastify.db.collection<TicketRecord>(TICKET_COLLECTION).insertOne(record);

    // The session now knows which clients hold tokens from it, so a logout can notify each of them.
    await fastify.db.collection<SessionRecord>(SESSION_COLLECTION).updateOne(
      { sessionId: session.sessionId },
      { $addToSet: { clientIds: client.clientId }, $set: { lastSeenAt: now.toISOString() } },
    );

    // The code itself is never in the event, nor is the state: what is recorded is that this client
    // obtained an authorization for this person, with this scope, in this flow.
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'token',
      action: 'authorization.code_issued',
      outcome: 'success',
      correlationId,
      clientId: client.clientId,
      subjectId: identity.subjectId,
      ...(ipHash ? { ipHash } : {}),
      target: { type: 'session', ref: session.sessionId },
      detail: {
        clientName: client.clientName,
        scope: requested,
        pkce: Boolean(body.code_challenge),
        softAdmitted,
      },
    });

    return reply.send({
      code,
      ...(body.state ? { state: body.state } : {}),
      redirect_uri: body.redirect_uri,
    });
  });
}
