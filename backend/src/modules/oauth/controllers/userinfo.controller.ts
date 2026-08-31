import { FastifyInstance } from 'fastify';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { DirectoryService } from '../../directory/services/directory.service';

/**
 * The UserInfo endpoint (OpenID Connect Core 1.0, section 5.3).
 *
 * It was advertised in the discovery document and never implemented, which is worse than not offering
 * it: a relying party reads the metadata, calls what it says is there, and gets a 404 it has to guess
 * the meaning of. The merchant did exactly that on every sign-in.
 *
 * What it returns is bounded by the SCOPES the access token carries, not by what the directory holds.
 * The same rule the ID token follows, so the two cannot disagree about what a client was allowed to
 * learn.
 */
export async function userinfoController(fastify: FastifyInstance) {
  const RESPONSE = {
    description: 'Claims about the subject, bounded by the granted scopes.',
    type: 'object',
    additionalProperties: true,
    required: ['sub'],
    properties: {
      sub: { type: 'string' },
      name: { type: 'string' },
      preferred_username: { type: 'string' },
      email: { type: 'string' },
      email_verified: { type: 'boolean' },
    },
    examples: [{ sub: 'a1b2c3', name: 'Ada Lovelace', preferred_username: 'ada', email: 'ada@example.com' }],
  };

  const schema = {
    tags: ['oauth'],
    summary: 'Claims about the authenticated subject',
    description:
      'OpenID Connect Core 1.0 section 5.3. Requires the access token issued to this subject. The '
      + 'claims returned are those the granted scopes permit: `profile` carries the name, `email` '
      + 'carries the address, and a scope that was not granted yields no claim rather than an error.',
    security: [{ bearerAuth: [] }],
    params: {
      type: 'object',
      required: ['realm'],
      properties: { realm: { type: 'string', examples: ['acme'] } },
    },
    response: {
      200: RESPONSE,
      401: { $ref: 'Problem#', description: 'No valid access token.' },
      404: { $ref: 'Problem#', description: 'The subject no longer exists in the directory.' },
    },
  };

  async function claimsFor(subjectId: string, scope: string[]) {
    const identity = await new DirectoryService(fastify.db).findBySubjectId(subjectId);
    if (!identity) return null;

    return {
      sub: identity.subjectId,
      // `profile` is what buys a display name. Without it a client learns only who, not what to call them.
      ...(scope.includes('profile')
        ? {
          ...(identity.name?.formatted ? { name: identity.name.formatted } : {}),
          preferred_username: identity.userName,
        }
        : {}),
      ...(scope.includes('email') && identity.primaryEmail
        ? { email: identity.primaryEmail, email_verified: false }
        : {}),
    };
  }

  // Both verbs, as the specification requires. A GET is what every client sends; a POST exists for
  // the ones that will not put a token in a URL-adjacent place, and returns the same thing.
  for (const method of ['get', 'post'] as const) {
    fastify[method]('/realms/:realm/protocol/openid-connect/userinfo', {
      preHandler: requirePrincipal,
      schema: { ...schema, operationId: `userinfo${method === 'get' ? '' : 'Post'}` },
    }, async (request, reply) => {
      const principal = request.principal!;
      const claims = await claimsFor(principal.subjectId, principal.scope);
      if (!claims) {
        return reply.status(404).send({
          type: 'about:blank',
          title: 'Unknown subject',
          status: 404,
          detail: 'The token is valid but its subject is no longer in the directory.',
        });
      }
      return reply.send(claims);
    });
  }
}
