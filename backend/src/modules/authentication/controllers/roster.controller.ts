import { FastifyInstance } from 'fastify';
import { createHash } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { LoginContextService } from '../services/loginContext.service';
import { problem } from '../../../shared/models/problem';

/**
 * What the sign-in screen needs: the realm's branding, its providers, and the demo roster.
 *
 * The roster is a demo affordance and it is load bearing for this product: a booth demonstration
 * runs on being able to sign in as a chosen persona in one click. Moving the login to the authority
 * without bringing the roster would preserve the security model and break the demonstration, which
 * is not a trade worth making.
 *
 * It discloses only what a sign-in screen already shows, and only for principals explicitly marked
 * as demo personas. A realm with none has an empty roster and an ordinary login form, which is what
 * a real deployment gets.
 */
export async function rosterController(fastify: FastifyInstance) {
  fastify.get('/realms/:realm/login-context', {
    schema: {
      operationId: 'getLoginContext',
      tags: ['authentication'],
      summary: 'What the sign-in screen renders',
      description:
        'No applicable standard. Branding, the federated providers a user may choose, and the demo '
        + 'roster when the realm declares one. Public, because it is what an unauthenticated visitor '
        + 'is about to be shown; it exposes nothing a sign-in page does not already display.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      querystring: {
        type: 'object',
        properties: {
          client_id: {
            type: 'string',
            description:
              'The application the person is signing in to. It already travels in the authorization '
              + 'request, so nothing extra is passed: the roster is narrowed to the roles that client '
              + 'declares, because the useful personas differ from one application to the next.',
            examples: ['acme-portal'],
          },
          request_id: {
            type: 'string',
            description:
              'The pending authorization the authority parked at the sign-in screen. Preferred over '
              + 'client_id from a hosted screen, which is not told which application asked.',
            examples: ['b3f1c2d4'],
          },
        },
      },
      response: {
        200: {
          description: 'Everything the sign-in screen needs, in one call.',
          type: 'object',
          additionalProperties: false,
          required: ['realm', 'branding', 'providers', 'roster'],
          properties: {
            realm: { type: 'string' },
            displayName: { type: 'string' },
            issuer: { type: 'string' },
            notice: { type: 'string' },
            registrationEnabled: { type: 'boolean' },
            branding: { type: 'object', additionalProperties: true },
            providers: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  name: { type: 'string' },
                  displayName: { type: 'string' },
                  protocol: { type: 'string' },
                  enabled: { type: 'boolean' },
                  notice: { type: 'string' },
                },
              },
            },
            roster: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  subjectId: { type: 'string' },
                  userName: { type: 'string', description: 'The login identifier, per SCIM.' },
                  displayName: { type: 'string', description: 'The name to show. SCIM `name.formatted`.' },
                  email: { type: 'string' },
                  role: { type: 'string' },
                  demoNote: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            realm: 'acme',
            displayName: 'Acme',
            branding: { displayName: 'Acme', primaryColor: '#00ED64' },
            providers: [{ name: 'entra', displayName: 'Microsoft Entra ID', protocol: 'oidc', enabled: false }],
            roster: [{ subjectId: 'ada', userName: 'ada.lovelace', displayName: 'Ada Lovelace', role: 'analyst' }],
          }],
        },
        304: { description: 'Unchanged since the tag the caller presented.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const { client_id: clientId, request_id: requestId } = request.query as {
      client_id?: string; request_id?: string;
    };

    /**
     * Which application is asking, which is the only thing about the caller that changes the answer:
     * the client's `demoRoster` names the roles its screen offers.
     *
     * A hosted screen is handed a `request_id` and is not told the client, so it is resolved from
     * the parked authorization. Read on every request rather than cached with the context: a ticket
     * is single use and short lived, and the CONTEXT is then cached on the client this resolves to,
     * which is what makes the cache hit across the many request ids of one session.
     */
    const { TICKET_COLLECTION } = await import('../../../shared/models/collections');
    const parked = requestId
      ? await fastify.db.collection(TICKET_COLLECTION).findOne(
        { realmId: realm.realmId, requestId },
        { projection: { _id: 0, clientId: 1 } },
      ) as { clientId?: string } | null
      : null;

    const { view, cached } = await new LoginContextService(fastify.db)
      .read(realm, parked?.clientId ?? clientId);

    /**
     * Revalidation, on a body that is identical between loads until the seed changes.
     *
     * The screen is loaded again on every redirect through the authority, so an unchanged answer is
     * worth answering with no body at all. The tag is a digest of the answer rather than a version
     * counter: nothing here has one, and a digest also covers branding and the domains.
     */
    const etag = `W/"${createHash('sha256').update(JSON.stringify(view)).digest('hex').slice(0, 32)}"`;
    // Seconds, and `private`: it is public data, but a shared cache holding a realm's sign-in screen
    // is a surprise nobody asked for, and a demo that reseeds must not need a hard refresh.
    reply.header('Cache-Control', 'private, max-age=30');
    reply.header('ETag', etag);
    // Observable, so a stale persona can be attributed instead of guessed at.
    reply.header('X-Login-Context-Cache', cached ? 'hit' : 'miss');
    if (request.headers['if-none-match'] === etag) return reply.status(304).send();

    return reply.send(view);
  });
}
