import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { oauthError } from '../../../shared/models/problem';
import { listOAuthClients } from '../services/clientAuth.service';
import { DEFAULT_AUTHORIZATION_DETAIL_TYPE } from '../services/authorizationDetails';

/**
 * Discovery and the published key set.
 *
 * Both are standard-defined and both are public by specification. Publishing them is not a
 * disclosure: the metadata says where the endpoints are, and the key set contains public keys whose
 * entire purpose is to be held by anyone who has to verify a signature.
 */
export async function discoveryController(fastify: FastifyInstance) {
  const realmService = () => new RealmService(fastify.db);
  const keyRing = () => new KeyRing(new MongoSigningKeyStore(fastify.db));

  const metadataSchema = {
    description: 'Authorization server metadata.',
    type: 'object',
    additionalProperties: true,
    required: ['issuer', 'jwks_uri'],
    properties: {
      issuer: { type: 'string' },
      authorization_endpoint: { type: 'string' },
      token_endpoint: { type: 'string' },
      userinfo_endpoint: { type: 'string' },
      jwks_uri: { type: 'string' },
      introspection_endpoint: { type: 'string' },
      revocation_endpoint: { type: 'string' },
      end_session_endpoint: { type: 'string' },
      backchannel_authentication_endpoint: { type: 'string' },
      scopes_supported: { type: 'array', items: { type: 'string' } },
      response_types_supported: { type: 'array', items: { type: 'string' } },
      grant_types_supported: { type: 'array', items: { type: 'string' } },
      subject_types_supported: { type: 'array', items: { type: 'string' } },
      id_token_signing_alg_values_supported: { type: 'array', items: { type: 'string' } },
      token_endpoint_auth_methods_supported: { type: 'array', items: { type: 'string' } },
      code_challenge_methods_supported: { type: 'array', items: { type: 'string' } },
    },
    examples: [{
      issuer: 'https://giam.example/realms/acme',
      jwks_uri: 'https://giam.example/realms/acme/protocol/openid-connect/certs',
    }],
  } as const;

  /**
   * Every scope a client in this realm may ask for.
   *
   * RFC 8414 2 lists it as RECOMMENDED and it was declared in the response schema and never emitted,
   * so a client had no way to discover what exists. Derived from the registrations rather than kept
   * as a second list: a scope no client may ask for is not a scope this realm supports, and a list
   * maintained beside the registrations is a list that drifts from them.
   *
   * P5 will attach a description and a required flag to each, once the resource catalog carries
   * them. This is the set, which is what a client needs first.
   */
  async function scopesSupported(realmId: string): Promise<string[]> {
    const clients = await listOAuthClients(fastify.db, realmId);
    const scopes = new Set<string>(['openid']);
    for (const client of clients) {
      for (const scope of (client.scope ?? '').split(' ').filter(Boolean)) scopes.add(scope);
    }
    return [...scopes].sort();
  }

  /**
   * What the realm can actually sign with, read from the published key set.
   *
   * It was the constant `['RS256']` while `key.model` declared `'RS256' | 'ES256'`, so the document
   * and the model disagreed and neither was checked against what the signer implements. Reading the
   * key set means the answer is what is true right now, and a realm that gains an ES256 key
   * advertises it without anybody remembering to.
   */
  async function signingAlgorithms(realmId: string): Promise<string[]> {
    const keySet = await keyRing().publishedKeySet(realmId);
    const algorithms = new Set<string>();
    for (const key of keySet.keys) if (key.alg) algorithms.add(key.alg);
    return algorithms.size > 0 ? [...algorithms].sort() : ['RS256'];
  }

  async function metadata(realmName: string) {
    const realm = await realmService().byName(realmName);
    if (!realm) return null;
    const base = `${realm.issuer}/protocol/openid-connect`;
    const [scopes, algorithms] = await Promise.all([
      scopesSupported(realm.realmId),
      signingAlgorithms(realm.realmId),
    ]);
    return {
      issuer: realm.issuer,
      authorization_endpoint: `${base}/auth`,
      token_endpoint: `${base}/token`,
      userinfo_endpoint: `${base}/userinfo`,
      jwks_uri: `${base}/certs`,
      introspection_endpoint: `${base}/token/introspect`,
      revocation_endpoint: `${base}/revoke`,
      end_session_endpoint: `${base}/logout`,
      backchannel_authentication_endpoint: `${base}/ext/ciba/auth`,
      response_types_supported: ['code'],
      grant_types_supported: [
        'authorization_code',
        'client_credentials',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:token-exchange',
        'urn:openid:params:grant-type:ciba',
      ],
      subject_types_supported: ['public'],
      scopes_supported: scopes,
      id_token_signing_alg_values_supported: algorithms,
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      // `query` is the default for the code flow and the only mode implemented. Advertising
      // `fragment` would invite a request the authorization endpoint refuses.
      response_modes_supported: ['query'],
      /**
       * The backchannel metadata, without which a CIBA client cannot discover whether poll, ping or
       * push is available. The grant was advertised and none of this was, so a conforming client had
       * to guess at the one thing it must not guess at.
       */
      backchannel_token_delivery_modes_supported: ['poll', 'ping', 'push'],
      backchannel_user_code_parameter_supported: false,
      /**
       * RFC 8707. A client narrows its own audience with `resource`, and it can only discover that
       * from here.
       */
      resource_indicators_supported: true,
      // RFC 9396, and the type this authority projects a constrained grant under. Deployment types
      // come from the resource catalog and are not advertised here, since they are its to declare.
      authorization_details_types_supported: [DEFAULT_AUTHORIZATION_DETAIL_TYPE],
      // S256 only. `plain` is in the specification and offers no protection at all, so supporting it
      // would advertise a downgrade a client could then choose.
      code_challenge_methods_supported: ['S256'],
      /**
       * Including the PRIVATE claims, which is the whole reason to list them.
       *
       * `session_epoch`, `admin_realms`, `account_holder` and `domain_id` have no specification
       * behind them, so a consumer can only learn they exist by being told. Declaring them here is
       * the mitigation for using short names rather than collision-resistant ones.
       */
      claims_supported: [
        'sub', 'iss', 'aud', 'exp', 'iat', 'jti', 'scope', 'client_id',
        'auth_time', 'acr', 'amr', 'sid', 'txn',
        'roles', 'entitlements', 'act', 'grant_id', 'authorization_details',
        'name', 'email', 'preferred_username',
        'session_epoch', 'admin_realms', 'account_holder', 'domain_id',
      ],
    };
  }

  /**
   * Both well-known locations, because the two specifications place the segment differently.
   *
   * OIDC Discovery 1.0 appends `/.well-known/openid-configuration` to the issuer, which is what the
   * first entry is. RFC 8414 3.1 says the opposite for an issuer that has path components: the
   * segment goes BETWEEN the host and the path, so the correct location is
   * `/.well-known/oauth-authorization-server/realms/{realm}`.
   *
   * Only the OIDC-shaped one was served, so a client following RFC 8414 to the letter got a 404 from
   * a server that does publish the document. The third entry keeps the old location working, since
   * it is what the consumers in this repository already fetch and it costs one route.
   */
  for (const [path, spec] of [
    ['/realms/:realm/.well-known/openid-configuration', 'OpenID Connect Discovery 1.0'],
    ['/.well-known/oauth-authorization-server/realms/:realm', 'RFC 8414 section 3.1'],
    ['/realms/:realm/.well-known/oauth-authorization-server', 'RFC 8414, the OIDC-shaped location'],
  ] as const) {
    fastify.get(path, {
      schema: {
        operationId: path.includes('openid-configuration')
          ? 'getOpenIdConfiguration'
          : (path.startsWith('/.well-known')
            ? 'getAuthorizationServerMetadata'
            : 'getAuthorizationServerMetadataAtIssuerPath'),
        tags: ['discovery'],
        summary: 'Authorization server metadata',
        description:
          `Standard-defined: ${spec}. Path, document and member names follow the specification `
          + 'verbatim. Public by specification: it names endpoints, it discloses nothing.',
        security: [],
        params: {
          type: 'object',
          required: ['realm'],
          properties: { realm: { type: 'string', examples: ['acme'] } },
        },
        response: {
          200: metadataSchema,
          404: { $ref: 'OAuthError#', description: 'No such realm.' },
        },
      },
    }, async (request, reply) => {
      const { realm } = request.params as { realm: string };
      const document = await metadata(realm);
      if (!document) return reply.status(404).send(oauthError('invalid_request', 'unknown realm', 404));
      return reply.send(document);
    });
  }

  fastify.get('/realms/:realm/protocol/openid-connect/certs', {
    schema: {
      operationId: 'getRealmKeySet',
      tags: ['discovery'],
      summary: 'JSON Web Key Set',
      description:
        'Standard-defined: RFC 7517. The realm\'s PUBLIC keys, which is what a resource server '
        + 'caches to verify locally. Every active key in the realm appears, including those held by '
        + 'other replicas, so a token signed by one verifies at all of them. Nothing private is here '
        + 'and nothing private ever will be.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      response: {
        200: {
          description: 'The realm key set.',
          type: 'object',
          required: ['keys'],
          properties: {
            keys: { type: 'array', items: { type: 'object', additionalProperties: true } },
          },
          examples: [{ keys: [{ kty: 'RSA', kid: 'abc', use: 'sig', alg: 'RS256', n: '…', e: 'AQAB' }] }],
        },
        404: { $ref: 'OAuthError#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const realm = await realmService().byName(realmName);
    if (!realm) return reply.status(404).send(oauthError('invalid_request', 'unknown realm', 404));
    // Cacheable, because it changes only on rotation and a stale copy is safe: an old public key can
    // validate only signatures the authority itself produced.
    reply.header('Cache-Control', 'public, max-age=300');
    return reply.send(await keyRing().publishedKeySet(realm.realmId));
  });
}
