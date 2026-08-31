import { FastifyInstance } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import { createHash } from 'crypto';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { SessionService } from '../services/session.service';
import { authenticationMethods } from '../../../shared/ports';
import { bindAuthenticationMethods } from '../services/authenticationMethods';
import { bindCredentialStores } from '../../directory/services/credentialStores';
import { SESSION_COLLECTION } from '../../../shared/models/collections';
import { SessionRecord } from '../models/session.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';

/**
 * Sign-in at the authority's own page.
 *
 * No applicable standard, and that is worth stating rather than reaching for a grant that looks
 * close. The resource-owner password grant is removed in OAuth 2.1 precisely because an application
 * should never collect a credential on the authority's behalf; here there is no application in the
 * middle, because this IS the authority's page. What it produces is a SESSION, and the standard flows
 * then run on top of it.
 *
 * A failure says only that the attempt failed. Distinguishing an unknown principal from a wrong
 * credential turns the endpoint into an account-enumeration oracle, and the person signing in cannot
 * act on the difference anyway.
 */
export async function loginController(fastify: FastifyInstance) {
  bindCredentialStores(fastify.db);
  bindAuthenticationMethods(fastify.db);

  fastify.post('/realms/:realm/login', {
    schema: {
      operationId: 'signIn',
      tags: ['authentication'],
      summary: 'Sign in and establish a session',
      description:
        'No applicable standard. Credential entry belongs at the authority, so this is its own page '
        + 'posting to its own endpoint rather than a grant an application could use. It establishes a '
        + 'session; the standard flows run on top of it. A failure never distinguishes an unknown '
        + 'principal from a wrong credential.',
      security: [],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['login', 'password'],
        additionalProperties: false,
        properties: {
          login: { type: 'string', description: 'User name or email.', examples: ['ada@example.com'] },
          password: { type: 'string' },
        },
      },
      response: {
        200: {
          description: 'Authenticated. A session now exists.',
          type: 'object',
          additionalProperties: false,
          required: ['subjectId', 'sessionId', 'assuranceLevel'],
          properties: {
            subjectId: { type: 'string' },
            sessionId: { type: 'string' },
            userName: { type: 'string' },
            assuranceLevel: { type: 'string' },
            method: { type: 'string' },
            sessionEpoch: { type: 'integer' },
          },
          examples: [{
            subjectId: 'ec06cbfa-96e2-4867-892b-b74987e78d7a',
            sessionId: 'a3f1…',
            userName: 'Ada Lovelace',
            assuranceLevel: 'aal1',
            method: 'password',
            sessionEpoch: 0,
          }],
        },
        401: { $ref: 'Problem#', description: 'The attempt failed. Deliberately no further detail.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName } = request.params as { realm: string };
    const { login, password } = request.body as { login: string; password: string };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm || !realm.enabled) {
      return reply.status(404).send(problem(404, 'Unknown realm'));
    }

    const method = authenticationMethods.resolve('password');
    const resolution = await method.authenticate({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      presented: { login, password },
      ipHash: hashIp(request.ip),
    });

    if (!resolution) {
      return reply.status(401).send(problem(401, 'Authentication failed'));
    }

    const directory = new DirectoryService(fastify.db);
    const identity = await directory.findBySubjectId(resolution.subjectId);

    // Built by the session service, so a password sign-in and a federated one produce exactly the
    // same session rather than two records that agree today and drift later.
    const session = await new SessionService(fastify.db).start({
      realm,
      subjectId: resolution.subjectId,
      epoch: identity?.sessionEpoch ?? 0,
      ...(request.headers['user-agent'] ? { userAgentHash: hashIp(String(request.headers['user-agent'])) as string } : {}),
      ...(request.ip ? { ipHash: hashIp(request.ip) as string } : {}),
    });

    return reply.send({
      subjectId: resolution.subjectId,
      sessionId: session.sessionId,
      userName: identity?.userName,
      assuranceLevel: resolution.assuranceLevel,
      method: resolution.method,
      sessionEpoch: session.epoch,
    });
  });
}

/** Hashed, never raw: an audit record and a session are not places to accumulate personal data. */
function hashIp(value: string | undefined): string | undefined {
  if (!value) return undefined;
  return createHash('sha256').update(value).digest('hex').slice(0, 32);
}
