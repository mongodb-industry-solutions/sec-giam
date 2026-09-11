import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { activeHoldings, toScimEmails } from '../../directory/models/principal.model';
import { scopeCatalogue } from '../../oauth/services/scopeCatalogue';
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
            askingApp: {
              type: 'object',
              additionalProperties: false,
              description:
                'The application the pending authorization names, so the sign-in screen can show '
                + 'who is asking before a credential is typed, the way a person expects to be told '
                + 'whose sign-in page they landed on. Present only for a hosted screen (`request_id`): '
                + 'a bare `client_id` names an application but not what it asked for THIS time, and '
                + 'showing scopes for a request that does not exist would be showing nothing real.',
              properties: {
                clientName: { type: 'string' },
                logoUri: { type: 'string' },
                scopes: {
                  type: 'array',
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                      name: { type: 'string' },
                      description: { type: 'string' },
                    },
                  },
                },
              },
            },
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
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const realmService = new RealmService(fastify.db);
    const realm = await realmService.byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const { client_id: clientId, request_id: requestId } = request.query as {
      client_id?: string; request_id?: string;
    };
    const { ROLE_COLLECTION, TICKET_COLLECTION } = await import('../../../shared/models/collections');

    /**
     * Everything below is independent of everything else here, so it is read at once rather than
     * as a waterfall: this endpoint is hit by an unauthenticated visitor on every load of the
     * sign-in screen, and a chain of round trips that were never sequenced ON PURPOSE is exactly
     * what turns a small answer into a slow one.
     */
    const [providers, roster, joining, parked, roles] = await Promise.all([
      realmService.providersFor(realm.realmId),
      new DirectoryService(fastify.db).demoRoster(realm.realmId),
      // Which path accepts joiners, resolved once for the response.
      realmService.registration(realm.realmId),
      // The hosted screen is given a request_id, not a client id, so the asking client is resolved
      // from the parked request rather than from a parameter that screen would have to carry.
      requestId
        ? fastify.db.collection(TICKET_COLLECTION).findOne(
          { realmId: realm.realmId, requestId },
          { projection: { _id: 0, clientId: 1, scope: 1 } },
        ) as Promise<{ clientId?: string; scope?: string } | null>
        : Promise.resolve(null),
      fastify.db.collection(ROLE_COLLECTION)
        .find({ realmId: realm.realmId }, { projection: { _id: 0, roleId: 1, name: 1 } })
        .toArray() as unknown as Promise<Array<{ roleId: string; name: string }>>,
    ]);

    /**
     * The role a persona holds, resolved so the screen can offer one ready-made user per role. This
     * is the "one click per role" affordance the demonstration is built around.
     *
     * Read straight off `roster`, not a second principal query: `demoRoster()` already returns
     * whole principal documents, `roles` embedded and all, so re-querying the SAME collection for
     * the SAME subjects for the SAME field was a round trip this endpoint never needed, on a screen
     * an unauthenticated visitor loads before doing anything else. `activeHoldings` is the one place
     * expiry and a pending approval are already handled, so a lapsed or unapproved holding is
     * excluded here exactly as it would be anywhere else that asks "what does this subject hold now".
     */
    const assignments = roster.flatMap(
      (identity) => activeHoldings(identity).map((holding) => ({ subjectId: identity.subjectId, roleId: holding.roleId })),
    );

    const roleNameById = new Map(roles.map((role) => [role.roleId, role.name]));

    // A persona can hold more than one role: the seed appends the realm administrator to whoever already
    // administers the realm. Collecting all of them, rather than keeping whichever the driver returned
    // last, is what stops those personas from being grouped under a role their screen never offers and
    // then filtered out of their own login list.
    const rolesBySubject = new Map<string, string[]>();
    for (const assignment of assignments) {
      const name = roleNameById.get(assignment.roleId);
      if (!name) continue;
      const held = rolesBySubject.get(assignment.subjectId);
      if (held) held.push(name);
      else rolesBySubject.set(assignment.subjectId, [name]);
    }

    // The roles this client's screen offers. Read from the client record rather than passed in, so a
    // caller cannot widen its own roster by asking for more.
    const askingClient = parked?.clientId ?? clientId;
    const { findOAuthClient } = await import('../../oauth/services/clientAuth.service');
    const client = askingClient ? await findOAuthClient(fastify.db, realm.realmId, askingClient) : null;
    const offered = client?.demoRoster;

    /**
     * Who is asking, and for what, before a credential is typed.
     *
     * Only for the hosted screen (`parked`, from a `request_id`): a bare `client_id` names an
     * application in general but not what THIS request asked for, and this platform's own console
     * used to resolve that ambiguity by rendering the sign-in page with no scopes to show at all,
     * which is one way of getting it wrong and not the other. Answered from the same catalogue the
     * consent screen reads, so the description of a scope cannot differ by which of the two asked.
     */
    const askingApp = parked && client
      ? {
        clientName: client.clientName,
        ...(client.logoUri ? { logoUri: client.logoUri } : {}),
        scopes: await (async () => {
          const catalogue = await scopeCatalogue(fastify.db, realm.realmId);
          return (parked.scope ?? '').split(' ').filter(Boolean).map((name) => ({
            name,
            ...(catalogue.get(name)?.description ? { description: catalogue.get(name)!.description } : {}),
          }));
        })()
      }
      : undefined;

    // The role this screen should show the persona under: the one it offers, when it offers any of them.
    const roleFor = (subjectId: string): string | undefined => {
      const held = rolesBySubject.get(subjectId) ?? [];
      return (offered && held.find((role) => offered.includes(role))) ?? held[0];
    };

    return reply.send({
      realm: realm.name,
      displayName: realm.displayName,
      issuer: realm.issuer,
      ...(realm.notice ? { notice: realm.notice } : {}),
      // Still one flag at the top level: a sign-in screen asks one question and should not have to
      // reason about which path answers it. Resolved from the internal path (ADR-002).
      registrationEnabled: joining.selfServiceEnabled,
      branding: realm.branding,
      ...(askingApp ? { askingApp } : {}),
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
          const role = roleFor(identity.subjectId);
          return Boolean(role && offered.includes(role));
        })
        .map((identity) => ({
          subjectId: identity.subjectId,
          // The login and the name are different things, and both are useful here: somebody
          // choosing a persona reads the name, and the field they then type is the login.
          userName: identity.userName,
          ...(identity.name?.formatted ? { displayName: identity.name.formatted } : {}),
          ...(toScimEmails(identity)[0] ? { email: toScimEmails(identity)[0].value } : {}),
          ...(roleFor(identity.subjectId) ? { role: roleFor(identity.subjectId) as string } : {}),
          ...(identity.demoNote ? { demoNote: identity.demoNote } : {}),
        })),
    });
  });
}
