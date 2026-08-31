import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { oauthError } from '../../../shared/models/problem';

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

  async function metadata(realmName: string) {
    const realm = await realmService().byName(realmName);
    if (!realm) return null;
    const base = `${realm.issuer}/protocol/openid-connect`;
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
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      // S256 only. `plain` is in the specification and offers no protection at all, so supporting it
      // would advertise a downgrade a client could then choose.
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email', 'preferred_username'],
    };
  }

  for (const [path, spec] of [
    ['/realms/:realm/.well-known/openid-configuration', 'OpenID Connect Discovery 1.0'],
    ['/realms/:realm/.well-known/oauth-authorization-server', 'RFC 8414'],
  ] as const) {
    fastify.get(path, {
      schema: {
        operationId: path.includes('openid') ? 'getOpenIdConfiguration' : 'getAuthorizationServerMetadata',
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
      if (!document) return reply.status(404).send(oauthError(404, 'unknown realm'));
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
    if (!realm) return reply.status(404).send(oauthError(404, 'unknown realm'));
    // Cacheable, because it changes only on rotation and a stale copy is safe: an old public key can
    // validate only signatures the authority itself produced.
    reply.header('Cache-Control', 'public, max-age=300');
    return reply.send(await keyRing().publishedKeySet(realm.realmId));
  });
}
