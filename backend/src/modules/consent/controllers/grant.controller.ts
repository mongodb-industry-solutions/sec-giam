import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { GrantService, GrantStatusFilter } from '../services/grant.service';
import { DecisionService } from '../../authorization/services/decision.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { isScopeChangeRefusal } from '../services/grant.service';
import { ClientAuthService } from '../../oauth/services/clientAuth.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { problem } from '../../../shared/models/problem';

/**
 * What a principal has authorised, and taking it back.
 *
 * Two callers reach these routes: a person looking at their own authorisations, and someone with an
 * oversight role looking at another's. The difference is decided HERE, by the decision point, and
 * never by the application that renders the page. A consumer that filters results after the fact has
 * not applied an access control, it has applied a presentation preference.
 */
export async function grantController(fastify: FastifyInstance) {
  const base = '/realms/:realm/grants';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const grantView = {
    type: 'object',
    additionalProperties: false,
    required: ['grantId', 'clientId', 'clientName', 'scopes', 'registeredScopes', 'status', 'grantedAt'],
    properties: {
      grantId: { type: 'string' },
      clientId: { type: 'string' },
      clientName: { type: 'string' },
      logoUri: { type: 'string' },
      scopes: { type: 'array', items: { type: 'string' }, description: 'What this application currently holds.' },
      registeredScopes: {
        type: 'array',
        items: { type: 'string' },
        description:
          'Everything the client is registered for, which is the ceiling a scope change is bounded '
          + 'by. Both halves travel together so a caller can offer the choice, rather than only ever '
          + 'taking permissions away.',
      },
      status: { type: 'string', enum: ['active', 'revoked'] },
      grantedAt: { type: 'string' },
      revokedAt: { type: 'string' },
      lastUsedAt: { type: 'string' },
    },
    examples: [{
      grantId: 'g-4c1f',
      clientId: 'acme-portal',
      clientName: 'Acme Portal',
      scopes: ['openid', 'profile'],
      registeredScopes: ['openid', 'profile', 'email'],
      status: 'active',
      grantedAt: '2026-08-01T10:22:00.000Z',
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /**
   * Whose grants the caller may see.
   *
   * Their own always. Another principal's only when a role they hold grants it, which is the same
   * decision point every other authorisation goes through: an oversight view is not a special case
   * with its own rules.
   */
  async function targetSubject(
    realmId: string,
    caller: { subjectId: string; clientId: string },
    requested: { subjectId?: string; accountHolderRef?: string },
    action: 'view' | 'manage' = 'view',
  ): Promise<{ subjectId: string } | { refused: string } | { missing: true }> {
    if (!requested.subjectId && !requested.accountHolderRef) return { subjectId: caller.subjectId };
    if (requested.subjectId === caller.subjectId) return { subjectId: caller.subjectId };

    const decision = await new DecisionService(fastify.db)
      .check(realmId, caller.subjectId, caller.clientId, 'grants', action);
    if (decision.effect !== 'allow') return { refused: decision.reason };

    if (requested.subjectId) return { subjectId: requested.subjectId };
    // Named by the business reference a consuming application knows them by. The authority resolves
    // which principal was bound to it without learning what the reference means.
    const identity = await new DirectoryService(fastify.db)
      .findByAccountHolderRef(realmId, requested.accountHolderRef as string);
    return identity ? { subjectId: identity.subjectId } : { missing: true };
  }

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listGrants',
      tags: ['consent'],
      summary: 'What this principal has authorised',
      description:
        'Standard-adjacent: the grants behind RFC 6749 authorisation, exposed so a person can review '
        + 'and withdraw them. A revoked grant is kept rather than deleted, because "what did I once '
        + 'allow, and when did I stop" is the question that matters after something goes wrong.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      querystring: {
        type: 'object',
        properties: {
          status: { type: 'string', enum: ['active', 'revoked', 'all'], default: 'all' },
          subjectId: {
            type: 'string',
            description: 'Another principal, for a caller whose role grants oversight. Refused otherwise.',
          },
          accountHolderRef: { type: 'string', description: 'The principal bound to this business reference. Same oversight rule as subjectId.' },
          clientId: { type: 'string', description: 'Everyone who has authorised this client. An oversight query, so it needs the same permission.' },
        },
      },
      response: {
        200: {
          description: 'The authorisations held.',
          type: 'object',
          additionalProperties: false,
          required: ['grants'],
          properties: { grants: { type: 'array', items: grantView } },
          examples: [{ grants: [grantView.examples[0]] }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants this oversight.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { status, subjectId, accountHolderRef, clientId } = request.query as { status?: GrantStatusFilter; subjectId?: string; accountHolderRef?: string; clientId?: string };
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const target = await targetSubject(realm.realmId, caller, { subjectId, accountHolderRef });
    if ('refused' in target) return reply.status(403).send(problem(403, 'Not permitted', target.refused));
    // A reference naming nobody answers exactly as a reference naming somebody with no grants would,
    // so this cannot be used to probe whether a principal exists.
    if ('missing' in target) return reply.status(404).send(problem(404, 'No such grant'));

    // Asking who has authorised a client is a question about other people, so it takes the same
    // permission as asking about another principal directly.
    if (clientId) {
      const oversight = await new DecisionService(fastify.db)
        .check(realm.realmId, caller.subjectId, caller.clientId, 'grants', 'view');
      if (oversight.effect !== 'allow') return reply.status(403).send(problem(403, 'Not permitted', oversight.reason));
      return reply.send({ grants: await new GrantService(fastify.db).listForClient(realm.realmId, clientId, status ?? 'all') });
    }

    return reply.send({
      grants: await new GrantService(fastify.db).list(realm.realmId, target.subjectId, status ?? 'all'),
    });
  });

  fastify.get(`${base}/:grantId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'getGrant',
      tags: ['consent'],
      summary: 'One authorisation',
      description:
        'Standard-adjacent: the grant behind RFC 6749 authorisation. Scoped to its owner in the query '
        + 'itself, so another principal\'s grant is not found rather than found and then refused: the '
        + 'two are indistinguishable to the caller, which is the point.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'grantId'],
        properties: { realm: { type: 'string' }, grantId: { type: 'string' } },
      },
      querystring: {
        type: 'object',
        properties: {
          subjectId: { type: 'string' },
          accountHolderRef: { type: 'string' },
        },
      },
      response: {
        200: { ...grantView, description: 'The authorisation.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants this oversight.' },
        404: { $ref: 'Problem#', description: 'No such grant for this principal.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, grantId } = request.params as { realm: string; grantId: string };
    const { subjectId, accountHolderRef } = request.query as { subjectId?: string; accountHolderRef?: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const target = await targetSubject(realm.realmId, caller, { subjectId, accountHolderRef });
    if ('refused' in target) return reply.status(403).send(problem(403, 'Not permitted', target.refused));
    // A reference naming nobody answers exactly as a reference naming somebody with no grants would,
    // so this cannot be used to probe whether a principal exists.
    if ('missing' in target) return reply.status(404).send(problem(404, 'No such grant'));

    const grant = await new GrantService(fastify.db).byId(realm.realmId, target.subjectId, grantId);
    if (!grant) return reply.status(404).send(problem(404, 'No such grant'));
    return reply.send(grant);
  });

  fastify.get(`${base}/:grantId/operations`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listGrantOperations',
      tags: ['consent'],
      summary: 'What was done under this authorisation',
      description:
        'No applicable standard. The identity trail for one grant, read from the security event '
        + 'record. What a client DID with the access is the consuming application\'s business trail '
        + 'and stays there: recording it here would create a second source of truth for it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'grantId'],
        properties: { realm: { type: 'string' }, grantId: { type: 'string' } },
      },
      querystring: {
        type: 'object',
        properties: {
          subjectId: { type: 'string' },
          accountHolderRef: { type: 'string' },
          limit: { type: 'integer', default: 100 },
        },
      },
      response: {
        200: {
          description: 'The identity events recorded under this authorisation.',
          type: 'object',
          additionalProperties: false,
          required: ['operations'],
          properties: {
            operations: {
              type: 'array',
              items: {
                type: 'object',
                additionalProperties: true,
                properties: {
                  ts: { type: 'string' },
                  action: { type: 'string' },
                  outcome: { type: 'string' },
                  clientId: { type: 'string' },
                },
              },
            },
          },
          examples: [{
            operations: [{
              ts: '2026-08-20T08:04:11.000Z',
              action: 'token.issued',
              outcome: 'success',
              clientId: 'acme-portal',
            }],
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held grants this oversight.' },
        404: { $ref: 'Problem#', description: 'No such grant for this principal.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, grantId } = request.params as { realm: string; grantId: string };
    const { subjectId, accountHolderRef, limit } = request.query as { subjectId?: string; accountHolderRef?: string; limit?: number };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const target = await targetSubject(realm.realmId, caller, { subjectId, accountHolderRef });
    if ('refused' in target) return reply.status(403).send(problem(403, 'Not permitted', target.refused));
    // A reference naming nobody answers exactly as a reference naming somebody with no grants would,
    // so this cannot be used to probe whether a principal exists.
    if ('missing' in target) return reply.status(404).send(problem(404, 'No such grant'));

    const grant = await new GrantService(fastify.db).byId(realm.realmId, target.subjectId, grantId);
    if (!grant) return reply.status(404).send(problem(404, 'No such grant'));

    const events = await new SecurityEventService(fastify.db).query({
      realmId: realm.realmId,
      subjectId: target.subjectId,
      clientId: grant.clientId,
      limit,
    });
    return reply.send({
      operations: events.map((event) => ({
        ts: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
        action: event.action,
        outcome: event.outcome,
        ...(event.meta.clientId ? { clientId: event.meta.clientId } : {}),
      })),
    });
  });

  /**
   * Changing what an application holds, in either direction.
   *
   * The gap this fills is one partial consent created. Before v41, a grant could be read or revoked
   * and nothing else, so somebody who declined a scope and later needed it had to withdraw the
   * application entirely and authorise it again from nothing. Now that declining a single scope is
   * possible, adding one back has to be too, or the narrow choice is a trap.
   *
   * The owner's own action. Withdrawal may be done on somebody's behalf by a role that grants it,
   * because taking access away is a containment step somebody else may legitimately need to take;
   * GIVING access back is not, so this route has no `subjectId` parameter at all.
   */
  fastify.patch(`${base}/:grantId`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'changeGrantScope',
      tags: ['consent'],
      summary: 'Change what an application is allowed to do',
      description:
        'Standard-adjacent: the scope of an RFC 6749 authorisation, changed after the fact. Bounded '
        + 'by the registration of the client, because those scopes were deduced from what its owner '
        + 'registered and a registration that can be exceeded is not a limit. Narrowing takes effect '
        + 'on the grant at once and ends the sessions of that client so the next token is minted '
        + 'narrower; a token already issued keeps its scope until it expires, which is minutes, '
        + 'because it is verified without calling here. Every change is recorded with the scope set '
        + 'before and after and who made it.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'grantId'],
        properties: { realm: { type: 'string' }, grantId: { type: 'string' } },
      },
      body: {
        type: 'object',
        required: ['scopes'],
        additionalProperties: false,
        properties: {
          scopes: {
            type: 'array',
            items: { type: 'string' },
            description: 'The complete set this application should hold. Not a delta: a set is unambiguous.',
          },
        },
      },
      response: {
        200: {
          description: 'What changed, and what it means for tokens already issued.',
          type: 'object',
          additionalProperties: false,
          required: ['before', 'after', 'added', 'removed'],
          properties: {
            before: { type: 'array', items: { type: 'string' } },
            after: { type: 'array', items: { type: 'string' } },
            added: { type: 'array', items: { type: 'string' } },
            removed: { type: 'array', items: { type: 'string' } },
            sessionsEnded: {
              type: 'integer',
              description: 'Ended so the next token is narrower. Tokens already issued run to expiry.',
            },
          },
          examples: [{ before: ['openid'], after: ['openid', 'profile'], added: ['profile'], removed: [], sessionsEnded: 0 }],
        },
        400: { $ref: 'Problem#', description: 'A scope beyond what the client is registered for.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        404: { $ref: 'Problem#', description: 'No such active authorisation for this person.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.principal!;
    const { realm: realmName, grantId } = request.params as { realm: string; grantId: string };
    const { scopes } = request.body as { scopes: string[] };

    const realm = await new RealmService(fastify.db).byName(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const grant = await new GrantService(fastify.db).byId(realm.realmId, caller.subjectId, grantId);
    if (!grant) return reply.status(404).send(problem(404, 'No such authorisation'));

    // The ceiling is the registration, read now rather than remembered: a client whose registration
    // narrowed since the grant was made should not keep a scope it may no longer be asked for.
    const client = await new ClientAuthService(fastify.db).find(realm.realmId, grant.clientId);
    const registered = (client?.scope ?? '').split(' ').filter(Boolean);

    const outcome = await new GrantService(fastify.db).changeScope(
      realm, caller.subjectId, grantId, scopes, { registeredScopes: registered },
    );

    if (isScopeChangeRefusal(outcome)) {
      if (outcome.refused === 'no_such_grant') {
        return reply.status(404).send(problem(404, 'No such authorisation'));
      }
      return reply.status(400).send(problem(
        400,
        'Beyond what this application is registered for',
        `${outcome.scopes.join(' ')} is not something ${grant.clientName} may be granted. `
        + 'Its registration is the ceiling, and raising that is a decision for the owner rather than you.',
      ));
    }

    /**
     * Narrowing ends that client's sessions, so the next token is minted with the new scope.
     *
     * Without this the change would take minutes to have any effect and would look, to the person
     * who made it, like nothing happened. It is not instantaneous even so, and the response says so
     * rather than implying otherwise.
     */
    let sessionsEnded = 0;
    if (outcome.removed.length > 0) {
      sessionsEnded = await new TokenIssuer(fastify.db, new KeyRing(new MongoSigningKeyStore(fastify.db)))
        .revokeClient(realm.realmId, outcome.clientId);
    }

    return reply.send({
      before: outcome.before,
      after: outcome.after,
      added: outcome.added,
      removed: outcome.removed,
      sessionsEnded,
    });
  });

  for (const [suffix, verb] of [['', 'revoke'], ['/reactivate', 'reactivate']] as const) {
    const revoking = verb === 'revoke';
    const route = `${base}/:grantId${suffix}`;
    const schema = {
      operationId: revoking ? 'revokeGrant' : 'reactivateGrant',
      tags: ['consent'],
      summary: revoking ? 'Withdraw an authorisation' : 'Restore a withdrawn authorisation',
      description:
        'Standard-adjacent: withdrawal of the consent behind RFC 6749 authorisation. '
        + (revoking
          ? 'A state change, never a delete, so the record of what was once allowed survives the '
            + 'withdrawal. The owner may always do it; anyone else needs a role that grants it, and '
            + 'that judgement is made here rather than by the application that offered the button.'
          : 'Restores a previously withdrawn authorisation without a fresh approval round, which is '
            + 'why it is the owner\'s own action and nobody else\'s.'),
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'grantId'],
        properties: { realm: { type: 'string' }, grantId: { type: 'string' } },
      },
      ...(revoking ? {
        querystring: {
          type: 'object',
          properties: {
            subjectId: { type: 'string', description: 'The owner, when withdrawing on their behalf. Needs a role that grants it.' },
            accountHolderRef: { type: 'string', description: 'The same, named by business reference.' },
          },
        },
      } : {}),
      response: {
        200: { ...grantView, description: 'The authorisation, in its new state.' },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits acting for another principal.' },
        404: {
          $ref: 'Problem#',
          description: revoking
            ? 'No active grant with that id for this principal.'
            : 'No withdrawn grant with that id for this principal.',
        },
      },
    };

    const handler = async (request: never, reply: never) => {
      const typed = request as unknown as {
        principal: { subjectId: string; clientId: string };
        params: { realm: string; grantId: string };
        query: { subjectId?: string; accountHolderRef?: string };
      };
      const answer = reply as unknown as { status: (code: number) => { send: (body: unknown) => unknown }; send: (body: unknown) => unknown };
      const { realm: realmName, grantId } = typed.params;
      const realm = await realmOf(realmName);
      if (!realm) return answer.status(404).send(problem(404, 'Unknown realm'));

      /**
       * Reactivation is the owner's alone, and withdrawal is not.
       *
       * The asymmetry is deliberate. Withdrawing somebody's authorisation takes access away, which is
       * the safe direction and a thing an oversight role legitimately needs during an investigation.
       * Restoring one gives access back without the person approving anything, so it stays with the
       * only party entitled to consent: them.
       */
      let owner = typed.principal.subjectId;
      if (revoking && (typed.query?.subjectId || typed.query?.accountHolderRef)) {
        const behalf = await targetSubject(realm.realmId, typed.principal, typed.query, 'manage');
        if ('refused' in behalf) return answer.status(403).send(problem(403, 'Not permitted', behalf.refused));
        if ('missing' in behalf) return answer.status(404).send(problem(404, 'No such grant in that state'));
        owner = behalf.subjectId;
      }

      const service = new GrantService(fastify.db);
      const changed = revoking
        ? await service.revoke(realm, owner, grantId, typed.principal.subjectId)
        : await service.reactivate(realm, owner, grantId, typed.principal.subjectId);
      if (!changed) return answer.status(404).send(problem(404, 'No such grant in that state'));

      return answer.send(await service.byId(realm.realmId, owner, grantId));
    };

    if (revoking) {
      fastify.delete(route, { preHandler: requirePrincipal, schema }, handler as never);
    } else {
      fastify.post(route, { preHandler: requirePrincipal, schema }, handler as never);
    }
  }
}
