import { FastifyInstance, FastifyReply } from 'fastify';
import { API_PREFIX } from '../../../shared/models/routes';
import { v4 as uuidv4 } from 'uuid';
import { createHash, randomBytes } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { ClientAuthService, provisionalClient, recordSoftAdmission } from '../services/clientAuth.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { TICKET_COLLECTION, SESSION_COLLECTION } from '../../../shared/models/collections';
import { TicketRecord } from '../models/ticket.model';
import { SessionRecord, isLive } from '../../authentication/models/session.model';
import { readSessionCookie } from '../../authentication/services/sessionCookie';
import { scopesOf, OAuthClient } from '../models/client.model';
import { scopeCatalogue } from '../services/scopeCatalogue';
import { enforcementFor } from '../../realm/models/realm.model';
import { newMeta } from '../../../shared/models/base.model';
import { oauthError } from '../../../shared/models/problem';
import type { OAuthErrorCode } from '../../../shared/models/problem';
import { SecurityEventService, hashIp } from '../../audit/services/securityEvent.service';
import { GrantService } from '../../consent/services/grant.service';
import { config } from '../../../config';

/**
 * The authorization endpoint, RFC 6749 section 4.1 with PKCE.
 *
 * A CONFORMING one, since v41 P4. What was here before could not be driven by any standard client:
 * it was a POST taking a JSON body, it returned the authorization code in a JSON response for the
 * caller to redirect with, it took the user's session as `session_id` in that body on a route
 * declared with no security, it accepted `consent_granted: true` as a boolean the caller asserted,
 * and it answered every refusal as a JSON 400 instead of redirecting. Each of those is a separate
 * departure from the specification, and together they made the flow GIAM-specific.
 *
 * The shape now:
 *
 * - `GET`, with the parameters in the query string, per section 3.1.
 * - A 302 to the registered redirect URI carrying `code` and `state`, per section 4.1.2.
 * - Errors delivered BY REDIRECT once the client and the redirect URI are known to be registered,
 *   per section 4.1.2.1, and answered directly only when they are not, because redirecting to an
 *   unverified URI is how an error becomes an open redirect.
 * - The session read from a cookie the browser holds, never from the request body.
 * - Consent recorded by the AUTHORITY against the pending request, so no caller can assert it.
 * - PKCE required of every client, per RFC 9700.
 *
 * The user interface stays where it was. This endpoint owns the FLOW and delegates the screens: with
 * no session it redirects to the sign-in page carrying `request_id`, and the person returns here.
 * That is the ordinary division for an authorization server, and it is what lets the pending request
 * survive a detour through two pages without the client having to hold it.
 */
export async function authorizeController(fastify: FastifyInstance) {
  const tickets = () => fastify.db.collection<TicketRecord>(TICKET_COLLECTION);

  /**
   * Where the person is sent to sign in, and to consent. The authority's own pages.
   *
   * `config.server.frontendUrl` rather than a new setting: it already names where this authority's
   * console lives and is already what CORS is configured against, so a second URL for the same thing
   * would be a second thing to get wrong.
   */
  const page = (
    path: string,
    realm: string,
    requestId: string,
    hints: Record<string, string | undefined> = {},
  ) => {
    const base = config.server.frontendUrl.replace(/\/$/, '');
    const url = new URL(`${base}${path}`);
    url.searchParams.set('realm', realm);
    url.searchParams.set('request_id', requestId);
    // Form prefill only, and only onto this authority's OWN page. Nothing here reaches the client or
    // widens the request: the parameters that decide what is authorized are read back from the
    // ticket, never from the URL the person returns with.
    for (const [key, value] of Object.entries(hints)) {
      if (value) url.searchParams.set(key, value);
    }
    return url.toString();
  };

  function redirectWith(reply: FastifyReply, redirectUri: string, values: Record<string, string | undefined>) {
    const url = new URL(redirectUri);
    for (const [key, value] of Object.entries(values)) {
      if (value !== undefined) url.searchParams.set(key, value);
    }
    return reply.redirect(url.toString(), 302);
  }

  await fastify.register(async (scoped) => {
    scoped.get('/realms/:realm/protocol/oidc/auth', {
      schema: {
        operationId: 'authorize',
        tags: ['oauth'],
        summary: 'Authorization endpoint',
        description:
          'Standard-defined: RFC 6749 section 4.1 and RFC 7636 (PKCE). Send a browser here with the '
          + 'parameters in the query string; the answer is a 302 to your registered redirect URI '
          + 'carrying `code` and `state`. Errors are delivered by redirect once the client and the '
          + 'redirect URI are known to be registered, and directly when they are not. PKCE is '
          + 'REQUIRED of every client, public or confidential, per RFC 9700. The session comes from '
          + 'a cookie, and consent is recorded by this authority rather than asserted by a caller.',
        security: [],
        params: {
          type: 'object',
          required: ['realm'],
          properties: { realm: { type: 'string', examples: ['acme'] } },
        },
        querystring: {
          type: 'object',
          additionalProperties: true,
          properties: {
            client_id: { type: 'string', examples: ['orders-web'] },
            redirect_uri: { type: 'string', examples: ['https://app.example/callback'] },
            response_type: { type: 'string', examples: ['code'] },
            scope: { type: 'string', examples: ['openid profile'] },
            state: { type: 'string' },
            nonce: { type: 'string' },
            code_challenge: { type: 'string', description: 'REQUIRED. RFC 7636.' },
            code_challenge_method: { type: 'string', examples: ['S256'] },
            response_mode: { type: 'string', examples: ['query'] },
            prompt: { type: 'string', description: 'OIDC: `consent` asks again even when a grant already covers the request.' },
            resource: {
              description: 'RFC 8707 resource indicators. Narrows the audience within the registration.',
              oneOf: [{ type: 'string' }, { type: 'array', items: { type: 'string' } }],
            },
            login_hint: {
              type: 'string',
              examples: ['luis.fernandez@back.es'],
              description:
                'OIDC 3.1.2.1. Who the client believes is signing in, used to prefill the login on '
                + 'the sign-in page of this authority. A hint only: the credential still has to be given, '
                + 'and nothing about the request changes if it is wrong.',
            },
            prefill_password: {
              type: 'string',
              description:
                'NON-STANDARD, and optional. Prefills the password field on the sign-in page so a '
                + 'demo can be walked in one click. Honoured because a simple integration is the '
                + 'point of it; a deployment with a real security model simply does not send it, '
                + 'since a credential in a query string reaches access logs, browser history and '
                + 'the Referer header. It is passed to the sign-in page and nowhere else: never '
                + 'stored on the request, never written to the trail.',
            },
            request_id: {
              type: 'string',
              description:
                'Returning from the sign-in or consent page. The pending request is read back from '
                + 'this rather than from the query, so a detour cannot alter what was asked for.',
            },
          },
        },
        response: {
          302: {
            // No body, so no schema. A redirect answers with `Location` and nothing else, and
            // declaring `type: 'null'` made the document claim it returns content that would then
            // need an example of a body which does not exist.
            description:
              'The authorization code, or an error, delivered to the registered redirect URI. Also '
              + 'the redirect to this authority\'s sign-in or consent page when one is needed.',
          },
          400: {
            /**
             * `allOf` around the reference, so the example survives beside it.
             *
             * A sibling of `$ref` is ignored by JSON Schema, so `{ $ref, examples }` silently loses
             * the example. This is the only response on this operation that has a body, since the
             * other is a redirect, so without an example the operation documents none at all.
             */
            allOf: [{ $ref: 'OAuthError#' }],
            description: 'The client or the redirect URI is not registered, so nothing may be redirected.',
            examples: [{ error: 'invalid_request', error_description: 'redirect_uri is not registered for this client' }],
          },
        },
      },
    }, async (request, reply) => {
      const { realm: realmName } = request.params as { realm: string };
      const query = request.query as Record<string, string | string[] | undefined>;
      const one = (name: string): string | undefined => {
        const value = query[name];
        return Array.isArray(value) ? value[0] : value;
      };

      const realm = await new RealmService(fastify.db).byName(realmName);
      // Not recorded, and answered directly: with no realm there is no trail to record it in and no
      // registration to have verified a redirect against.
      if (!realm || !realm.enabled) {
        return reply.status(400).send(oauthError('invalid_request', 'unknown realm'));
      }

      const ipHash = hashIp(request.ip);

      /**
       * Returning from a detour: the request is read back from the TICKET, not from the query.
       *
       * That is a correctness property rather than a convenience. If the parameters were re-read
       * from the URL, a sign-in or consent page could be re-entered with a different scope or a
       * different redirect than the person was shown, and the consent they gave would not be the
       * consent that was exercised.
       */
      const resumeId = one('request_id');
      const resumed = resumeId
        ? await tickets().findOne({ realmId: realm.realmId, requestId: resumeId }, { projection: { _id: 0 } })
        : null;
      if (resumeId && !resumed) {
        return reply.status(400).send(oauthError('invalid_request', 'that request has expired, start again'));
      }

      const clientId = resumed?.clientId ?? one('client_id');
      const redirectUri = resumed?.redirectUri ?? one('redirect_uri');
      if (!clientId || !redirectUri) {
        return reply.status(400).send(oauthError('invalid_request', 'client_id and redirect_uri are required'));
      }

      const registered = await new ClientAuthService(fastify.db).find(realm.realmId, clientId);
      const softAdmitted = !registered && enforcementFor(realm) === 'soft';
      if (registered && registered.status !== 'active') {
        return reply.status(400).send(oauthError('unauthorized_client', 'unknown client'));
      }
      if (!registered && !softAdmitted) {
        return reply.status(400).send(oauthError('invalid_request', 'unknown client'));
      }
      const client = registered ?? provisionalClient(realm, clientId, [redirectUri]);

      /**
       * Exact match, never a prefix, and answered DIRECTLY.
       *
       * RFC 6749 4.1.2.1: with an invalid redirect URI the authorization server MUST NOT
       * automatically redirect. Doing so would deliver an error, and the `state` with it, to a URI
       * nobody verified, which is an open redirect wearing an error response.
       */
      if (!client.redirectUris.includes(redirectUri)) {
        return reply.status(400).send(oauthError('invalid_request', 'redirect_uri is not registered for this client'));
      }

      // Everything from here is redirected to a URI this authority has verified.
      const state = resumed?.state ?? one('state');

      const refuse = (code: OAuthErrorCode, description: string, cause: string, subjectId?: string) => {
        void new SecurityEventService(fastify.db).record({
          realmId: realm.realmId,
          tenantId: realm.tenantId,
          category: 'token',
          action: 'authorization.code_issued',
          outcome: 'failure',
          cause,
          correlationId: resumed?.requestId ?? request.correlationId,
          clientId: client.clientId,
          ...(subjectId ? { subjectId } : {}),
          ...(ipHash ? { ipHash } : {}),
          detail: { responseType: one('response_type'), scope: resumed?.scope ?? one('scope') },
        });
        return redirectWith(reply, redirectUri, { error: code, error_description: description, state });
      };

      const responseType = resumed ? 'code' : one('response_type');
      if (responseType !== 'code') {
        return refuse('unsupported_response_type', 'only the authorization code flow is supported', 'unsupported_response_type');
      }

      /**
       * `response_mode`, validated rather than ignored.
       *
       * `query` is the default for the code flow and the only mode implemented. Accepting the
       * parameter silently would tell a client asking for `fragment` that it had been honoured.
       */
      const responseMode = one('response_mode');
      if (responseMode && responseMode !== 'query') {
        return refuse('unsupported_response_mode', `response_mode ${responseMode} is not supported`, 'unsupported_response_mode');
      }

      /**
       * PKCE, REQUIRED of every client.
       *
       * It was conditional on `client.requirePkce`, while discovery advertised
       * `code_challenge_methods_supported: ["S256"]` and RFC 9700 2.1.1 requires it of public and
       * confidential clients alike. A per-client opt-out is an opt-out from the mitigation for code
       * interception, and no registration should be able to choose that.
       */
      const codeChallenge = resumed?.pkce?.challenge ?? one('code_challenge');
      const codeChallengeMethod = resumed?.pkce?.method ?? one('code_challenge_method') ?? 'S256';
      if (!codeChallenge) {
        return refuse('invalid_request', 'code_challenge is required (RFC 7636)', 'pkce_missing');
      }
      if (codeChallengeMethod !== 'S256') {
        return refuse('invalid_request', 'code_challenge_method must be S256', 'pkce_method_unsupported');
      }

      // On a resume this is the ticket's scope, which the consent decision may have NARROWED. Taking
      // it from the query instead would re-widen the request after the person cut it down.
      const asked = (resumed?.scope ?? one('scope') ?? 'openid').split(' ').filter(Boolean);
      const permitted = scopesOf(client);
      // Narrowed for a soft admission, which IS the limit soft mode applies, and refused for a
      // registered client, because silently dropping a scope would leave it believing it holds
      // authority it does not.
      const requested = softAdmitted ? permitted : asked;
      const beyond = softAdmitted ? [] : asked.filter((scope) => !permitted.includes(scope));
      if (beyond.length > 0) {
        return refuse('invalid_scope', `scope not permitted: ${beyond.join(' ')}`, 'scope_not_permitted');
      }

      const resources = (Array.isArray(query.resource) ? query.resource : [query.resource])
        .filter((entry): entry is string => typeof entry === 'string' && entry.length > 0);

      if (softAdmitted) {
        await recordSoftAdmission(fastify.db, realm, {
          clientId: client.clientId,
          endpoint: 'authorize',
          address: request.ip,
        });
      }

      /**
       * The pending request, created before the person is sent anywhere.
       *
       * It is what lets the flow survive a detour through the sign-in page and the consent page: the
       * parameters are held HERE, so neither page can alter them and the client does not have to
       * carry them through. Its `requestId` is also the flow correlator that becomes the `txn`
       * claim, so an attempt that never reaches a token is still filed under a flow.
       */
      const pending: TicketRecord = resumed ?? {
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        requestId: uuidv4(),
        flow: 'authorization_code',
        clientId: client.clientId,
        status: 'pending',
        pkce: { challenge: codeChallenge, method: 'S256' },
        redirectUri,
        ...(state ? { state, stateHash: createHash('sha256').update(state).digest('hex').slice(0, 16) } : {}),
        ...(one('nonce') ? { nonce: one('nonce') as string } : {}),
        // The standard hint is kept with the request, the way the backchannel flow already keeps it.
        // `prefill_password` deliberately is NOT: a credential does not belong in a stored record.
        ...(one('login_hint') ? { loginHint: one('login_hint') as string } : {}),
        ...(resources.length ? { resources } : {}),
        scope: requested.join(' '),
        attemptCount: 0,
        expiresAt: new Date(Date.now() + realm.tokenPolicy.codeTtlSeconds * 1000).toISOString(),
        meta: newMeta('AuthorizationRequest'),
      };
      if (!resumed) await tickets().insertOne(pending);

      /**
       * The session, from the COOKIE.
       *
       * With none, the person is sent to sign in and comes back here. This endpoint never accepts a
       * credential and never accepts a session identifier from a caller: keeping credential entry in
       * one place is the whole reason an authority exists.
       */
      const sessionId = readSessionCookie(request);
      const session = sessionId
        ? await fastify.db.collection<SessionRecord>(SESSION_COLLECTION)
          .findOne({ realmId: realm.realmId, sessionId }, { projection: { _id: 0 } })
        : null;

      if (!session || !isLive(session)) {
        // `prompt=none` says do not interact, so a missing session is an error rather than a page.
        if (one('prompt') === 'none') {
          return refuse('login_required', 'no live session and prompt=none was requested', 'no_live_session');
        }
        return reply.redirect(page('/auth/login', realm.name, pending.requestId, {
          login_hint: pending.loginHint ?? one('login_hint'),
          prefill_password: one('prefill_password'),
        }), 302);
      }

      const identity = await new DirectoryService(fastify.db).findBySubjectId(session.subjectId);
      if (!identity) return refuse('login_required', 'no live session', 'subject_no_longer_exists');

      /**
       * Has this person agreed to hand their identity to this application?
       *
       * The answer is the authority's to record. It was a boolean the CALLER supplied
       * (`consent_granted: true`), with a comment saying a client should never set it and nothing
       * preventing it, on an endpoint declared with no security. Consent is now recorded against
       * this pending request by `POST .../auth/consent`, which requires the session cookie, so the
       * only party that can approve is the person the browser is signed in as.
       */
      if (!client.firstParty) {
        const grants = new GrantService(fastify.db);
        /**
         * Only what is MISSING is asked about, which is what makes consent incremental.
         *
         * A client already holding `openid profile` that now asks for `payments:read` is asked
         * about `payments:read`. Asking about all three would make widening a scope look, to the
         * person, exactly like a first authorisation, so they would learn nothing from the screen.
         */
        const missing = one('prompt') === 'consent'
          ? requested
          : await grants.missing(realm.realmId, identity.subjectId, client.clientId, requested);

        if (missing.length > 0 && pending.status !== 'approved') {
          return reply.redirect(page('/auth/consent', realm.name, pending.requestId), 302);
        }
        if (missing.length > 0) await grants.consent(realm, identity.subjectId, client, requested);
      }

      const code = randomBytes(32).toString('base64url');
      const now = new Date();
      await tickets().updateOne(
        { requestId: pending.requestId },
        {
          $set: {
            status: 'approved',
            subjectId: identity.subjectId,
            sessionId: session.sessionId,
            // Hashed at rest, for the same reason a password is: reading this collection must not
            // leave anybody able to redeem an outstanding authorization.
            codeHash: createHash('sha256').update(code).digest('hex'),
            ...(session.domainId ? { domainId: session.domainId } : {}),
            ...(session.credentialId ? { credentialId: session.credentialId } : {}),
            // Short by design: a code is a bearer credential in a URL, and its window should be the
            // time a browser needs one redirect, not the time a person needs to read a page.
            expiresAt: new Date(now.getTime() + realm.tokenPolicy.codeTtlSeconds * 1000).toISOString(),
            'meta.lastModified': now.toISOString(),
          },
        },
      );

      // The session now knows which clients hold tokens from it, so a logout can notify each.
      await fastify.db.collection<SessionRecord>(SESSION_COLLECTION).updateOne(
        { sessionId: session.sessionId },
        { $addToSet: { clientIds: client.clientId }, $set: { lastSeenAt: now.toISOString() } },
      );

      // Neither the code nor the state is in the event: what is recorded is that this client
      // obtained an authorization for this person, with this scope, in this flow.
      void new SecurityEventService(fastify.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'token',
        action: 'authorization.code_issued',
        outcome: 'success',
        correlationId: pending.requestId,
        clientId: client.clientId,
        subjectId: identity.subjectId,
        ...(ipHash ? { ipHash } : {}),
        target: { type: 'session', ref: session.sessionId },
        detail: {
          clientName: client.clientName,
          scope: requested,
          pkce: true,
          softAdmitted,
          // Everything an investigation needs about the REQUEST, recorded now: the ticket expires in
          // minutes by design, so anything only on the ticket is gone before an audit reads it.
          pkceMethod: 'S256',
          redirectUri,
          scopeAsked: asked,
          ...(session.domainId ? { domainId: session.domainId } : {}),
          ...(resources.length ? { resources } : {}),
        },
      });

      return redirectWith(reply, redirectUri, { code, state });
    });

    /**
     * What the person is being asked to approve.
     *
     * The consent page is sent nothing but a `request_id`, deliberately: if it were handed the
     * client name and the scopes in the URL, whoever built that URL would decide what the person
     * reads, and a consent screen showing something other than what will be exercised is worse than
     * no consent screen. So the page asks, and the answer is assembled from the STORED request.
     *
     * Requires the session cookie, because this discloses which application is asking for what, and
     * that is the person's business rather than anybody's who holds a request id.
     */
    scoped.get('/realms/:realm/protocol/oidc/auth/consent', {
      schema: {
        operationId: 'readConsentPrompt',
        tags: ['oauth'],
        summary: 'What a pending authorization is asking for',
        description:
          'No applicable standard for this shape; what is standard-defined is that the decision '
          + 'belongs to the resource owner, so the screen must show what will actually be exercised. '
          + 'Reads back a pending authorization, assembled from the STORED request rather than from '
          + 'the URL, so nothing a caller writes decides what the person is shown. Requires the '
          + 'session cookie.',
        security: [],
        params: {
          type: 'object',
          required: ['realm'],
          properties: { realm: { type: 'string' } },
        },
        querystring: {
          type: 'object',
          required: ['request_id'],
          properties: { request_id: { type: 'string' } },
        },
        response: {
          200: {
            description: 'The application, and what it is asking for.',
            type: 'object',
            additionalProperties: false,
            required: ['clientName', 'scopes'],
            properties: {
              clientName: { type: 'string' },
              clientUri: { type: 'string' },
              logoUri: { type: 'string' },
              scopes: {
                type: 'array',
                description:
                  'One entry per scope, with what it means to a person. The description comes from '
                  + 'the resource server that accepts the scope, so this authority renders a '
                  + 'the vocabulary of the deployment rather than carrying one of its own.',
                items: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['name', 'required', 'alreadyGranted'],
                  properties: {
                    name: { type: 'string' },
                    description: { type: 'string' },
                    required: { type: 'boolean', description: 'Declining it ends the flow rather than narrowing it.' },
                    alreadyGranted: { type: 'boolean', description: 'Held from an earlier authorisation.' },
                  },
                },
              },
            },
            examples: [{
              clientName: 'Acme Accounting',
              scopes: [
                { name: 'openid', description: 'Confirm who you are', required: true, alreadyGranted: true },
                { name: 'profile', description: 'Read your name', required: false, alreadyGranted: false },
              ],
            }],
          },
          400: {
            allOf: [{ $ref: 'OAuthError#' }],
            description: 'No such pending request, or it has expired.',
            examples: [{ error: 'invalid_request', error_description: 'no such pending request' }],
          },
          401: {
            allOf: [{ $ref: 'OAuthError#' }],
            description: 'No live session, so there is nobody to ask.',
            examples: [{ error: 'access_denied', error_description: 'no live session' }],
          },
        },
      },
    }, async (request, reply) => {
      const { realm: realmName } = request.params as { realm: string };
      const { request_id: requestId } = request.query as { request_id: string };

      const realm = await new RealmService(fastify.db).byName(realmName);
      if (!realm || !realm.enabled) {
        return reply.status(400).send(oauthError('invalid_request', 'unknown realm'));
      }

      const sessionId = readSessionCookie(request);
      const session = sessionId
        ? await fastify.db.collection<SessionRecord>(SESSION_COLLECTION)
          .findOne({ realmId: realm.realmId, sessionId }, { projection: { _id: 0, expiresAt: 1, idleExpiresAt: 1, subjectId: 1 } })
        : null;
      if (!session || !isLive(session as SessionRecord)) {
        return reply.status(401).send(oauthError('access_denied', 'no live session', 401));
      }

      const pending = await tickets().findOne(
        { realmId: realm.realmId, requestId },
        { projection: { _id: 0, clientId: 1, scope: 1, status: 1 } },
      );
      if (!pending || pending.status === 'consumed') {
        return reply.status(400).send(oauthError('invalid_request', 'no such pending request'));
      }

      const client = await new ClientAuthService(fastify.db).find(realm.realmId, pending.clientId);
      const asked = pending.scope.split(' ').filter(Boolean);
      const catalogue = await scopeCatalogue(fastify.db, realm.realmId);
      const held = new Set(await new GrantService(fastify.db)
        .grantedScopesFor(realm.realmId, session.subjectId, pending.clientId));

      return reply.send({
        clientName: client?.clientName ?? pending.clientId,
        ...(client?.clientUri ? { clientUri: client.clientUri } : {}),
        ...(client?.logoUri ? { logoUri: client.logoUri } : {}),
        scopes: asked.map((name) => ({
          name,
          ...(catalogue.get(name)?.description ? { description: catalogue.get(name)!.description } : {}),
          // `openid` is required by nature: without it there is no identity to hand over, so
          // declining it is declining the whole request rather than narrowing it.
          required: catalogue.get(name)?.required ?? name === 'openid',
          alreadyGranted: held.has(name),
        })),
      });
    });

    /**
     * The person's decision on a pending request.
     *
     * Separate from the authorization endpoint, and requiring the session cookie, because that is
     * what makes it the PERSON's decision. The caller supplies only which pending request they are
     * answering; who is answering comes from the cookie, and what is being approved comes from the
     * stored request. A client cannot reach this on somebody's behalf.
     */
    scoped.post('/realms/:realm/protocol/oidc/auth/consent', {
      schema: {
        operationId: 'recordConsent',
        tags: ['oauth'],
        summary: 'Record the person\'s decision on a pending authorization',
        description:
          'No applicable standard for the shape; what is standard-defined is that the decision '
          + 'belongs to the resource owner. Requires the session cookie, so the only party who can '
          + 'approve is the person the browser is signed in as. Answers with where to continue, '
          + 'which is the authorization endpoint carrying the same `request_id`.',
        security: [],
        params: {
          type: 'object',
          required: ['realm'],
          properties: { realm: { type: 'string' } },
        },
        body: {
          type: 'object',
          required: ['request_id', 'approved'],
          additionalProperties: false,
          properties: {
            request_id: { type: 'string' },
            approved: { type: 'boolean', description: 'False sends `access_denied` back to the application.' },
            granted_scopes: {
              type: 'array',
              items: { type: 'string' },
              description:
                'The scopes the person actually approved, which may be FEWER than were asked for. '
                + 'RFC 6749 3.3 permits granting a narrower scope than requested, and 5.1 requires '
                + 'the token response to say so. Omitted means all of them. Anything not asked for '
                + 'is ignored rather than granted: a decision can only narrow.',
            },
          },
        },
        response: {
          200: {
            description: 'Recorded. Send the browser to `continue`.',
            type: 'object',
            additionalProperties: false,
            required: ['continue'],
            properties: {
              continue: { type: 'string', description: 'The authorization endpoint, carrying the request id.' },
            },
            examples: [{
              continue: 'https://authority.example/api/v1/realms/acme/protocol/oidc/auth?request_id=6f2c1a44',
            }],
          },
          400: { $ref: 'OAuthError#', description: 'No such pending request, or it has expired.' },
          401: { $ref: 'OAuthError#', description: 'No live session, so there is nobody to consent.' },
        },
      },
    }, async (request, reply) => {
      const { realm: realmName } = request.params as { realm: string };
      const body = request.body as { request_id: string; approved: boolean; granted_scopes?: string[] };

      const realm = await new RealmService(fastify.db).byName(realmName);
      if (!realm || !realm.enabled) {
        return reply.status(400).send(oauthError('invalid_request', 'unknown realm'));
      }

      const sessionId = readSessionCookie(request);
      const session = sessionId
        ? await fastify.db.collection<SessionRecord>(SESSION_COLLECTION)
          .findOne({ realmId: realm.realmId, sessionId }, { projection: { _id: 0 } })
        : null;
      if (!session || !isLive(session)) {
        return reply.status(401).send(oauthError('access_denied', 'no live session', 401));
      }

      const pending = await tickets().findOne(
        { realmId: realm.realmId, requestId: body.request_id },
        { projection: { _id: 0 } },
      );
      if (!pending || pending.status === 'consumed') {
        return reply.status(400).send(oauthError('invalid_request', 'no such pending request'));
      }

      const client = await new ClientAuthService(fastify.db).find(realm.realmId, pending.clientId);
      const scopes = pending.scope.split(' ').filter(Boolean);

      if (!body.approved) {
        await tickets().updateOne(
          { requestId: pending.requestId },
          { $set: { status: 'denied', cause: 'consent_declined', subjectId: session.subjectId } },
        );
        void new SecurityEventService(fastify.db).record({
          realmId: realm.realmId,
          tenantId: realm.tenantId,
          category: 'consent',
          action: 'grant.declined',
          outcome: 'success',
          subjectId: session.subjectId,
          clientId: pending.clientId,
          correlationId: pending.requestId,
          detail: { scope: scopes },
        });
        // Back to the application as an OAuth error, which is the relying party's to explain in its
        // own terms. Stranding somebody on the authority with a message about a client they never
        // chose is the failure this whole path exists to avoid.
        const url = new URL(pending.redirectUri as string);
        url.searchParams.set('error', 'access_denied');
        url.searchParams.set('error_description', 'The person declined to authorise this application.');
        if (pending.state) url.searchParams.set('state', pending.state);
        return reply.send({ continue: url.toString() });
      }

      /**
       * The subset the person approved, which may be FEWER scopes than were asked for.
       *
       * RFC 6749 3.3 permits granting a narrower scope than requested, and 5.1 requires the token
       * response to say so. Consent used to be all-or-nothing here, which was MORE restrictive than
       * the specification and gained nothing: a person who wanted to withhold one scope had to
       * decline the application entirely.
       *
       * Intersected with what was asked, never unioned. A decision naming a scope nobody requested
       * is ignored rather than granted, so approving cannot widen a request, which is what makes it
       * safe to let the browser send this at all.
       */
      const asked = new Set(scopes);
      const granted = body.granted_scopes
        ? body.granted_scopes.filter((scope) => asked.has(scope))
        : scopes;

      /**
       * A required scope that was withheld ends the flow rather than narrowing it.
       *
       * Without `openid` there is no identity to hand over, so a token missing it would satisfy
       * nothing the client asked for. Reported as `access_denied`, which is what declining is.
       */
      const catalogue = await scopeCatalogue(fastify.db, realm.realmId);
      const withheldRequired = scopes.filter(
        (scope) => (catalogue.get(scope)?.required ?? scope === 'openid') && !granted.includes(scope),
      );
      if (withheldRequired.length > 0) {
        await tickets().updateOne(
          { requestId: pending.requestId },
          { $set: { status: 'denied', cause: 'required_scope_declined', subjectId: session.subjectId } },
        );
        const denied = new URL(pending.redirectUri as string);
        denied.searchParams.set('error', 'access_denied');
        denied.searchParams.set(
          'error_description',
          `The person declined a scope this request cannot proceed without: ${withheldRequired.join(' ')}.`,
        );
        if (pending.state) denied.searchParams.set('state', pending.state);
        return reply.send({ continue: denied.toString() });
      }

      if (client) {
        await new GrantService(fastify.db).consent(realm, session.subjectId, client as OAuthClient, granted);
      }
      await tickets().updateOne(
        { requestId: pending.requestId },
        {
          $set: {
            status: 'approved',
            subjectId: session.subjectId,
            // What is EXERCISED is what was granted, so the token cannot carry a scope the person
            // withheld. Writing it back here is what makes the narrowing real rather than cosmetic.
            scope: granted.join(' '),
          },
        },
      );

      // The BROWSER-facing origin, not the issuer: the issuer is this authority's discovery identity,
      // which a deployment may keep in-network, and a browser sent there would carry no cookie a
      // same-origin sign-in put on the public host, landing back on sign-in with a live session.
      const base = config.server.frontendUrl.replace(/\/$/, '');
      return reply.send({
        continue: `${base}${API_PREFIX}/realms/${realm.name}/protocol/oidc/auth?request_id=${encodeURIComponent(pending.requestId)}`,
      });
    });
  });
}
