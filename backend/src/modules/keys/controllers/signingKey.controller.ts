import { FastifyInstance } from 'fastify';
import { RealmService } from '../../realm/services/realm.service';
import { KeyAdminService, isKeyRefusal } from '../services/keyAdmin.service';
import { authorityAccess, refusal } from '../../authorization/services/authorityAccess';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requirePrincipal } from '../../../vendors/middleware/principalAuth';
import { problem } from '../../../shared/models/problem';

/**
 * The realm's signing keys: what is published, what is signing, and what is on its way out.
 *
 * No response here carries private material at any authorization level, and that is not a projection
 * being careful: the private half never reaches the database in the first place, so there is nothing
 * to withhold. The three lifecycle operations are separate permissions on purpose. Reading the key
 * set tells an operator what verifies; rotating adds a key and takes nothing away; retiring stops
 * publication and breaks every token already signed with it. Granting all three under one name would
 * mean the person who may look is the person who may cause an outage.
 *
 * Administering a realm, so this whole surface is closed to an ordinary registered user.
 */
export async function signingKeyController(fastify: FastifyInstance) {
  const base = '/realms/:realm/signing-keys';

  const realmParam = {
    type: 'object',
    required: ['realm'],
    properties: { realm: { type: 'string', examples: ['acme'] } },
  } as const;

  const keyView = {
    type: 'object',
    additionalProperties: false,
    required: ['kid', 'keyId', 'algorithm', 'use', 'provider', 'status', 'phase', 'phaseReason', 'signingEligible', 'leaseLapsed', 'notBefore', 'ownedByThisInstance', 'externalCustody'],
    properties: {
      kid: { type: 'string', description: 'RFC 7638 thumbprint. What a verifier resolves against the published set.' },
      keyId: { type: 'string' },
      algorithm: { type: 'string', enum: ['RS256', 'ES256'] },
      use: { type: 'string', enum: ['sig'] },
      keySize: { type: 'integer' },
      provider: { type: 'string', description: 'The custody mode that holds the private half.' },
      status: { type: 'string', enum: ['active', 'deprecated', 'revoked'] },
      phase: {
        type: 'string',
        enum: ['signing', 'published', 'retired', 'revoked'],
        description: 'Signing, or lapsed but still published so what it signed keeps verifying, or past its grace.',
      },
      phaseReason: { type: 'string' },
      instanceId: { type: 'string', description: 'Which replica holds the private half. Absent when custody is external.' },
      ownedByThisInstance: { type: 'boolean' },
      externalCustody: { type: 'boolean' },
      leaseExpiresAt: { type: 'string' },
      leaseLapsed: { type: 'boolean' },
      signingEligible: { type: 'boolean' },
      notBefore: { type: 'string' },
      notAfter: { type: 'string', description: 'When it stops being published. Until then a verifier still accepts it.' },
      rotatedAt: { type: 'string' },
    },
    examples: [{
      kid: 'Yx3-8fQb1Rk2m0PZq7cJd5AeT9nLpUvB',
      keyId: 'key-Yx3-8fQb1Rk2m0',
      algorithm: 'RS256',
      use: 'sig',
      keySize: 2048,
      provider: 'instance-local',
      status: 'active',
      phase: 'signing',
      phaseReason: 'Offered for signing by the replica that holds it, and published for verification.',
      instanceId: 'giam-0',
      ownedByThisInstance: true,
      externalCustody: false,
      leaseExpiresAt: '2026-08-31T10:05:00.000Z',
      leaseLapsed: false,
      signingEligible: true,
      notBefore: '2026-08-31T10:00:00.000Z',
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  /** Tier two, and the named action. Reading, rotating and retiring are three different authorities. */
  async function administers(realmId: string, subjectId: string, action: string) {
    const access = await authorityAccess(fastify.db, realmId, subjectId);
    if (!access.can('keys', action) || !access.realmWide) return { refused: refusal('keys', action) };
    return { access };
  }

  /**
   * One key lifecycle operation, recorded either way.
   *
   * The outcome is a parameter rather than a constant: an attempt to retire a realm's signing key by
   * somebody whose roles do not permit it is the entry worth having, and a helper hardcoded to
   * success is a helper that can only ever describe the days nothing went wrong.
   */
  function audit(
    realm: { realmId: string; tenantId: string },
    action: string,
    subjectId: string,
    detail: Record<string, unknown>,
    outcome: 'success' | 'failure' = 'success',
    cause?: string,
  ) {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'key',
      action,
      outcome,
      subjectId,
      ...(cause ? { cause } : {}),
      detail,
    });
  }

  fastify.get(base, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'listSigningKeys',
      tags: ['keys'],
      summary: 'The realm\'s published key set',
      description:
        'No applicable standard for this administrative view; the keys themselves are RFC 7517 and '
        + 'are served publicly at the realm\'s JWKS endpoint. This one adds custody: which replica '
        + 'holds each private half, whether its lease is still current, and whether a key that '
        + 'stopped signing is still published so tokens already signed with it keep verifying. No '
        + 'private material appears in this response at any authorization level.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'Every key in the realm\'s set, and the custody mode in force.',
          type: 'object',
          additionalProperties: false,
          required: ['keys', 'provider', 'externalCustody', 'rotatable', 'instanceId'],
          properties: {
            keys: { type: 'array', items: keyView },
            provider: { type: 'string' },
            externalCustody: { type: 'boolean', description: 'True when the private key is held outside this deployment.' },
            rotatable: { type: 'boolean', description: 'False when rotation belongs where custody is, not here.' },
            instanceId: { type: 'string', description: 'This replica, so "yours" is answerable in the list.' },
            leaseSeconds: { type: 'integer' },
            publicationGraceSeconds: { type: 'integer', description: 'How long a lapsed key stays published, at least the maximum token lifetime.' },
          },
          examples: [{
            keys: [keyView.examples[0]],
            provider: 'instance-local',
            externalCustody: false,
            rotatable: true,
            instanceId: 'giam-0',
            leaseSeconds: 300,
            publicationGraceSeconds: 3600,
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held administers this realm.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const gate = await administers(realm.realmId, request.principal!.subjectId, 'view');
    if ('refused' in gate) return reply.status(403).send(problem(403, 'Not permitted', gate.refused));

    return reply.send(await new KeyAdminService(fastify.db).list(realm.realmId));
  });

  fastify.post(`${base}/rotate`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'rotateSigningKey',
      tags: ['keys'],
      summary: 'Replace this replica\'s signing key',
      description:
        'No applicable standard. The new key is published before the old one stops signing, so the '
        + 'realm is never without a signer, and the old one keeps its place in the published set for '
        + 'the grace period because the tokens it signed have not expired. Refused when custody is '
        + 'external: a provider that reported success while the key stayed where it was would be '
        + 'worse than one that says it cannot.',
      security: [{ bearerAuth: [] }],
      params: realmParam,
      response: {
        200: {
          description: 'The new key, and what became of the old one.',
          type: 'object',
          additionalProperties: false,
          required: ['kid'],
          properties: {
            kid: { type: 'string' },
            previousKid: { type: 'string' },
            previousPublishedUntil: { type: 'string', description: 'Until when the outgoing key still verifies.' },
          },
          examples: [{
            kid: 'Nq7-2bWc9Xt4h1RGm8vJz3EyD6sKpAoL',
            previousKid: 'Yx3-8fQb1Rk2m0PZq7cJd5AeT9nLpUvB',
            previousPublishedUntil: '2026-08-31T11:00:00.000Z',
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits rotating this realm\'s keys.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'Custody is external, so rotation does not belong here.' },
      },
    },
  }, async (request, reply) => {
    const realm = await realmOf((request.params as { realm: string }).realm);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'rotate');
    if ('refused' in gate) {
      audit(realm, 'key.rotated', caller.subjectId, {}, 'failure', 'not_permitted');
      return reply.status(403).send(problem(403, 'Not permitted', gate.refused));
    }

    const outcome = await new KeyAdminService(fastify.db).rotate(realm.realmId, realm.tenantId);
    if (isKeyRefusal(outcome)) {
      audit(realm, 'key.rotated', caller.subjectId, { title: outcome.title }, 'failure', 'external_custody');
      return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));
    }

    audit(realm, 'key.rotated', caller.subjectId, outcome as unknown as Record<string, unknown>);
    return reply.send(outcome);
  });

  fastify.post(`${base}/:kid/retire`, {
    preHandler: requirePrincipal,
    schema: {
      operationId: 'retireSigningKey',
      tags: ['keys'],
      summary: 'Stop publishing a key',
      description:
        'No applicable standard. Withdrawing a key from the published set means every token signed '
        + 'with it stops verifying, including ones somebody is holding right now. That is the right '
        + 'action for a key believed compromised and the wrong one for tidiness, so a key still '
        + 'inside its publication window is refused until the caller acknowledges the breakage.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'kid'],
        properties: { realm: { type: 'string' }, kid: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          acknowledgeTokenBreakage: {
            type: 'boolean',
            default: false,
            description: 'Required while the key is still published, because live tokens depend on it.',
          },
        },
      },
      response: {
        200: {
          description: 'Withdrawn from the published set.',
          type: 'object',
          additionalProperties: false,
          required: ['retired', 'kid'],
          properties: { retired: { type: 'boolean' }, kid: { type: 'string' }, warning: { type: 'string' } },
          examples: [{
            retired: true,
            kid: 'Yx3-8fQb1Rk2m0PZq7cJd5AeT9nLpUvB',
            warning: 'This key is still published. Tokens already signed with it stop verifying the moment it is withdrawn, so anybody holding one is signed out at their next request.',
          }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token.' },
        403: { $ref: 'Problem#', description: 'No role held permits retiring this realm\'s keys.' },
        404: { $ref: 'Problem#', description: 'No such key in this realm.' },
        409: { $ref: 'Problem#', description: 'Live tokens depend on it and the breakage was not acknowledged, or it is already out of the set.' },
      },
    },
  }, async (request, reply) => {
    const { realm: realmName, kid } = request.params as { realm: string; kid: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const caller = request.principal!;
    const gate = await administers(realm.realmId, caller.subjectId, 'retire');
    if ('refused' in gate) {
      audit(realm, 'key.retired', caller.subjectId, { kid }, 'failure', 'not_permitted');
      return reply.status(403).send(problem(403, 'Not permitted', gate.refused));
    }

    const { acknowledgeTokenBreakage } = (request.body ?? {}) as { acknowledgeTokenBreakage?: boolean };
    const outcome = await new KeyAdminService(fastify.db)
      .retire(realm.realmId, kid, { acknowledged: Boolean(acknowledgeTokenBreakage) });
    if (outcome === null) {
      audit(realm, 'key.retired', caller.subjectId, { kid }, 'failure', 'no_such_key');
      return reply.status(404).send(problem(404, 'No such key'));
    }
    if (isKeyRefusal(outcome)) {
      // Refused because live tokens still depend on it and nobody acknowledged the breakage. Worth
      // recording: it is an operator being stopped from signing everybody out unintentionally.
      audit(realm, 'key.retired', caller.subjectId, { kid, title: outcome.title }, 'failure', 'breakage_not_acknowledged');
      return reply.status(outcome.status as 409).send(problem(outcome.status, outcome.title, outcome.detail));
    }

    audit(realm, 'key.retired', caller.subjectId, { kid });
    return reply.send({ retired: true, kid, ...(outcome.warning ? { warning: outcome.warning } : {}) });
  });
}
