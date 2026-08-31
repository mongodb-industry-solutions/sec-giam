import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { toScimEmails } from '../../directory/models/identity.model';
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
                  userName: { type: 'string' },
                  email: { type: 'string' },
                  role: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            realm: 'acme',
            displayName: 'Acme',
            branding: { displayName: 'Acme', primaryColor: '#00ED64' },
            providers: [{ name: 'entra', displayName: 'Microsoft Entra ID', protocol: 'oidc', enabled: false }],
            roster: [{ subjectId: 'ada', userName: 'Ada Lovelace', role: 'analyst' }],
          }],
        },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const realmService = new RealmService(fastify.db);
    const realm = await realmService.byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const providers = await realmService.providersFor(realm.realmId);
    const roster = await new DirectoryService(fastify.db).demoRoster(realm.realmId);

    // The role a persona holds, resolved so the screen can offer one ready-made user per role. This
    // is the "one click per role" affordance the demonstration is built around.
    const { ROLE_ASSIGNMENT_COLLECTION, ROLE_COLLECTION } = await import('../../../shared/models/collections');
    const assignments = await fastify.db.collection(ROLE_ASSIGNMENT_COLLECTION)
      .find({ realmId: realm.realmId }, { projection: { _id: 0, subjectId: 1, roleId: 1 } })
      .toArray() as unknown as Array<{ subjectId: string; roleId: string }>;
    const roles = await fastify.db.collection(ROLE_COLLECTION)
      .find({ realmId: realm.realmId }, { projection: { _id: 0, roleId: 1, name: 1 } })
      .toArray() as unknown as Array<{ roleId: string; name: string }>;

    const roleNameById = new Map(roles.map((role) => [role.roleId, role.name]));
    const roleBySubject = new Map(assignments.map((a) => [a.subjectId, roleNameById.get(a.roleId)]));

    // The roles this client's screen offers. Read from the client record rather than passed in, so a
    // caller cannot widen its own roster by asking for more.
    const { client_id: clientId } = request.query as { client_id?: string };
    const { CLIENT_COLLECTION } = await import('../../../shared/models/collections');
    const client = clientId
      ? await fastify.db.collection(CLIENT_COLLECTION).findOne(
        { realmId: realm.realmId, clientId, status: 'active' },
        { projection: { _id: 0, demoRoster: 1 } },
      ) as { demoRoster?: string[] } | null
      : null;
    const offered = client?.demoRoster;

    return reply.send({
      realm: realm.name,
      displayName: realm.displayName,
      issuer: realm.issuer,
      ...(realm.notice ? { notice: realm.notice } : {}),
      registrationEnabled: realm.registration.selfServiceEnabled,
      branding: realm.branding,
      providers: providers.map((provider) => ({
        name: provider.name,
        displayName: provider.displayName,
        protocol: provider.protocol,
        enabled: provider.enabled,
        ...(provider.notice ? { notice: provider.notice } : {}),
      })),
      roster: roster
        // An unknown client, or one that declares nothing, gets every featured persona: that is the
        // behaviour a realm with no application-specific screen should have.
        .filter((identity) => {
          if (!offered) return true;
          const role = roleBySubject.get(identity.subjectId);
          return Boolean(role && offered.includes(role));
        })
        .map((identity) => ({
          subjectId: identity.subjectId,
          userName: identity.userName,
          ...(toScimEmails(identity)[0] ? { email: toScimEmails(identity)[0].value } : {}),
          ...(roleBySubject.get(identity.subjectId) ? { role: roleBySubject.get(identity.subjectId) as string } : {}),
        })),
    });
  });
}
