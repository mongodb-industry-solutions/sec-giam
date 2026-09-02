import { FastifyInstance } from 'fastify';
import { Filter } from 'mongodb';
import { randomUUID, randomBytes } from 'crypto';
import * as bcrypt from 'bcryptjs';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { requireAuthorityCaller, AuthorityCaller } from '../../../vendors/middleware/authorityAuth';
import { OAuthClient, clientFromCredential, clientMetadata } from '../models/client.model';
import { CredentialRecord } from '../../directory/models/credential.model';
import { clientCredentials, clientFilter, clientUpdate } from '../services/clientRegistry';
import { withinActiveSecretCap } from '../../directory/models/credential.model';
import { newMeta } from '../../../shared/models/base.model';
import { problem } from '../../../shared/models/problem';
import {
  checkGrantTypes, checkRedirectUris, checkScopes, firstPartyHosts, hostOf, isRefusal,
  SELF_SERVICE_CLIENT_LIMIT,
} from '../services/clientRegistrationPolicy';

/**
 * Registering an application, so a consumer never holds a client secret it minted itself.
 *
 * Registration is self-service. A person building an integration registers their own application and
 * owns it, and the authority holds the credential: it is the only party that ever sees the secret in
 * the clear. A consumer that generates client secrets has a credential store, a hashing decision and
 * a rotation policy of its own, and it will get one of those subtly wrong in a way nobody notices
 * until the audit.
 *
 * The difference between a person and an administrator here is SCOPE, not access. A caller whose
 * roles are self-scoped sees and changes the applications they own; a caller holding the realm-wide
 * permission sees and changes every one. The narrowing is applied in the query, never after the fact,
 * and a client outside the caller's reach is NOT FOUND rather than refused, because telling somebody
 * that an identifier exists is itself an answer.
 *
 * Ownership is a SET and it is many to many. A person owns several applications and an application
 * has several owners, because two people sharing responsibility for one integration is the normal
 * case. Every owner holds the same authority as every other, and a registration can never reach zero
 * owners: at that point nobody but an operator credential could administer it again.
 */
export async function clientRegistrationController(fastify: FastifyInstance) {
  const base = '/realms/:realm/clients';

  /** How a self-registered client records the person who owns it. */
  const OWNER_KIND = 'principal';

  const clientView = {
    type: 'object',
    additionalProperties: true,
    required: ['client_id', 'client_name'],
    properties: {
      client_id: { type: 'string' },
      client_name: { type: 'string' },
      client_secret: {
        type: 'string',
        description: 'Returned ONCE, at registration or rotation, and never retrievable afterwards.',
      },
      client_type: { type: 'string', enum: ['confidential', 'public'] },
      redirect_uris: { type: 'array', items: { type: 'string' } },
      post_logout_redirect_uris: { type: 'array', items: { type: 'string' } },
      grant_types: { type: 'array', items: { type: 'string' } },
      scope: { type: 'string' },
      logo_uri: { type: 'string' },
      application_type: { type: 'string' },
      token_endpoint_auth_method: { type: 'string' },
      require_pkce: { type: 'boolean' },
      status: { type: 'string' },
      owners: {
        type: 'array',
        description: 'Everyone who administers this registration. Every owner holds the same authority.',
        items: {
          type: 'object',
          additionalProperties: true,
          required: ['kind', 'ref'],
          properties: {
            kind: { type: 'string' },
            ref: { type: 'string' },
            display_name: { type: 'string' },
            is_caller: { type: 'boolean' },
          },
        },
      },
      owned_by_caller: { type: 'boolean', description: 'Whether the caller is one of the owners.' },
      created_at: { type: 'string' },
      last_modified_at: { type: 'string' },
    },
    examples: [{
      client_id: 'acme-portal',
      client_name: 'Acme Portal',
      client_type: 'confidential',
      redirect_uris: ['https://acme.example/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      scope: 'openid profile',
      status: 'active',
      owners: [{ kind: 'principal', ref: 'sub-9f21', display_name: 'Ada Lovelace', is_caller: true }],
      owned_by_caller: true,
    }],
  } as const;

  async function realmOf(name: string) {
    return new RealmService(fastify.db).byName(name);
  }

  function clients() {
    return clientCredentials(fastify.db);
  }

  /** One registration, as the flat client the rest of this controller reads. */
  async function findClient(flat: Record<string, unknown>): Promise<OAuthClient | null> {
    const found = await clients().findOne(clientFilter(flat), { projection: { _id: 0 } });
    return found ? clientFromCredential(found) : null;
  }

  /**
   * One registry event, recorded.
   *
   * Refusals go through here too. A registration refused because the caller reached their limit, or
   * claimed a host that belongs to somebody else, or asked for a grant self-service does not offer, is
   * the shape of somebody probing the registry, and a trail holding only the successes cannot show it.
   */
  function audit(
    realm: { realmId: string; tenantId: string },
    caller: AuthorityCaller,
    input: {
      action: string;
      outcome: 'success' | 'failure';
      cause?: string;
      clientId?: string;
      target?: { type: string; ref: string };
      stakeholderSubjectIds?: string[];
      detail?: Record<string, unknown>;
    },
  ): void {
    void new SecurityEventService(fastify.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'lifecycle',
      ...input,
      ...(caller.subjectId ? { subjectId: caller.subjectId } : {}),
      detail: { ...(input.detail ?? {}), viaOperatorToken: caller.viaOperatorToken },
    });
  }

  /**
   * The people who administer a registration, as the stakeholder list of an event about it.
   *
   * Only principals: a tenant reference is a consuming application's own record and not somebody who
   * signs in here, so putting it in a list that grants sight of a trail would name a reader that does
   * not exist. Read from the record as it stands at the moment of the change, because that is the set
   * the change actually concerned.
   */
  function ownerSubjects(record: OAuthClient, ...also: Array<string | undefined>): string[] {
    const owners = (record.owners ?? [])
      .filter((owner) => owner.kind === OWNER_KIND)
      .map((owner) => owner.ref);
    return [...new Set([...owners, ...also.filter((ref): ref is string => Boolean(ref))])];
  }

  /**
   * Whether this caller acts over the whole realm for one kind of change.
   *
   * Both halves are required. The permission says the caller administers registrations at all; the
   * role's scope says how far that reaches. A self-scoped role holding the permission is still
   * limited to its own records, which is what keeps "administrator" a deliberate grant rather than a
   * side effect of holding any role at all.
   */
  function administers(caller: AuthorityCaller, action: 'view' | 'manage' | 'rotateSecret'): boolean {
    return caller.can('clients', action) && caller.scopeKind === 'all';
  }

  /**
   * Membership of the owner set, as a query fragment.
   *
   * Never a check in a handler. The narrowing has to happen in the read itself, so a registration the
   * caller does not own is not found rather than found and then refused: the two are indistinguishable
   * to the caller, which is the point.
   */
  function ownedBy(subjectId: string | undefined): Record<string, unknown> {
    // An operator credential is nobody in particular, so it owns nothing. Matching nothing is the
    // honest answer, and it beats a sentinel value that a real record could one day collide with.
    if (!subjectId) return { clientId: { $in: [] } };
    return { owners: { $elemMatch: { kind: OWNER_KIND, ref: subjectId } } };
  }

  /** The set of registrations this caller may act on, expressed as a query rather than a filter. */
  function reach(
    caller: AuthorityCaller,
    realmId: string,
    action: 'view' | 'manage' | 'rotateSecret',
  ): Filter<OAuthClient> {
    if (administers(caller, action)) return { realmId } as Filter<OAuthClient>;
    return { realmId, ...ownedBy(caller.subjectId) } as unknown as Filter<OAuthClient>;
  }

  /** The same membership question in memory, for a record already read under a narrowed query. */
  function isOwner(record: OAuthClient, subjectId: string | undefined): boolean {
    if (!subjectId) return false;
    return (record.owners ?? []).some((owner) => owner.kind === OWNER_KIND && owner.ref === subjectId);
  }

  function ownerView(owner: { kind: string; ref: string; displayName?: string }, caller: AuthorityCaller) {
    return {
      kind: owner.kind,
      ref: owner.ref,
      ...(owner.displayName ? { display_name: owner.displayName } : {}),
      // So the console can mark which one is the reader without comparing subject ids itself.
      is_caller: owner.kind === OWNER_KIND && owner.ref === caller.subjectId,
    };
  }

  function view(record: OAuthClient, caller: AuthorityCaller): Record<string, unknown> {
    const owners = record.owners ?? [];
    return {
      client_id: record.clientId,
      client_name: record.clientName,
      client_type: record.clientType,
      redirect_uris: record.redirectUris ?? [],
      post_logout_redirect_uris: record.postLogoutRedirectUris ?? [],
      grant_types: record.grantTypes ?? [],
      scope: record.scope ?? '',
      ...(record.logoUri ? { logo_uri: record.logoUri } : {}),
      ...(record.applicationType ? { application_type: record.applicationType } : {}),
      token_endpoint_auth_method: record.tokenEndpointAuthMethod,
      require_pkce: record.requirePkce,
      status: record.status,
      owners: owners.map((owner) => ownerView(owner, caller)),
      owned_by_caller: owners.some((owner) => owner.kind === OWNER_KIND && owner.ref === caller.subjectId),
      ...(record.meta?.created ? { created_at: record.meta.created } : {}),
      ...(record.meta?.lastModified ? { last_modified_at: record.meta.lastModified } : {}),
    };
  }

  /**
   * A secret is shown once and stored only as a hash.
   *
   * Anything else means the authority can hand somebody's credential back to whoever asks next, and
   * "we can look it up for you" is indistinguishable from "anyone who reaches this can have it".
   */
  async function mintSecret(): Promise<{ secret: string; hash: string; prefix: string }> {
    const secret = randomBytes(32).toString('base64url');
    // The leading characters, kept in the clear so an operator can tell two secrets apart in a list
    // during a rotation window without either being recoverable from what they are looking at.
    return { secret, hash: await bcrypt.hash(secret, 12), prefix: secret.slice(0, 6) };
  }

  /** Hosts a self-registered client may not claim: this platform's own, and every other party's. */
  async function reservedHosts(realmId: string, subjectId: string | undefined): Promise<Set<string>> {
    const reserved = firstPartyHosts();
    const others = (await clients().find(
      clientFilter({ realmId, $nor: [ownedBy(subjectId)] }),
      { projection: { _id: 0 } },
    ).toArray()).map(clientFromCredential);
    for (const other of others) {
      for (const uri of [...(other.redirectUris ?? []), ...(other.postLogoutRedirectUris ?? [])]) {
        const host = hostOf(uri);
        if (host) reserved.add(host);
      }
    }
    return reserved;
  }

  fastify.get(base, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'listClients',
      tags: ['oauth'],
      summary: 'The applications registered here',
      description:
        'Standard-adjacent: the registry behind RFC 7591 dynamic client registration, which defines '
        + 'no listing of its own. A caller sees the applications they own; a caller holding the '
        + 'realm-wide permission sees every one. The narrowing happens in the query, because a filter '
        + 'applied after the fact is a presentation choice rather than an access control. No secret '
        + 'and no secret hash is returned at any level of authority.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      querystring: {
        type: 'object',
        properties: {
          type: { type: 'string', enum: ['confidential', 'public'] },
          status: { type: 'string', enum: ['active', 'suspended', 'revoked'] },
          q: { type: 'string', description: 'Matches part of the application name or its identifier.' },
          limit: { type: 'integer', minimum: 1, maximum: 200, default: 20 },
          offset: { type: 'integer', minimum: 0, default: 0 },
        },
      },
      response: {
        200: {
          description: 'The registrations within the caller\'s reach.',
          type: 'object',
          additionalProperties: false,
          required: ['clients', 'total', 'limit', 'offset', 'scope'],
          properties: {
            clients: { type: 'array', items: clientView },
            total: { type: 'integer' },
            limit: { type: 'integer' },
            offset: { type: 'integer' },
            scope: {
              type: 'string',
              enum: ['self', 'all'],
              description: 'What this listing covered: only the caller\'s own, or the whole realm.',
            },
          },
          examples: [{ clients: [clientView.examples[0]], total: 1, limit: 20, offset: 0, scope: 'self' }],
        },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName } = request.params as { realm: string };
    const query = request.query as { type?: string; status?: string; q?: string; limit?: number; offset?: number };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const limit = Math.min(Math.max(query.limit ?? 20, 1), 200);
    const offset = Math.max(query.offset ?? 0, 0);

    const filter: Record<string, unknown> = { ...reach(caller, realm.realmId, 'view') };
    if (query.type) filter.clientType = query.type;
    if (query.status) filter.status = query.status;
    if (query.q) {
      // Escaped, so a search box cannot become an expression the database evaluates.
      const term = query.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { clientName: { $regex: term, $options: 'i' } },
        { clientId: { $regex: term, $options: 'i' } },
      ];
    }

    const translated = clientFilter(filter);
    const [records, total] = await Promise.all([
      clients()
        .find(translated, { projection: { _id: 0 } })
        .sort({ 'metadata.clientName': 1 })
        .skip(offset)
        .limit(limit)
        .toArray(),
      clients().countDocuments(translated),
    ]);

    return reply.send({
      clients: records.map((record) => view(clientFromCredential(record), caller)),
      total,
      limit,
      offset,
      scope: administers(caller, 'view') ? 'all' : 'self',
    });
  });

  fastify.get(`${base}/:clientId`, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'getClient',
      tags: ['oauth'],
      summary: 'One registered application',
      description:
        'Standard-defined: RFC 7592 client configuration read. The secret is not here and never will '
        + 'be: it is shown once at registration and once at rotation, and the authority stores only a '
        + 'hash of it. A registration outside the caller\'s reach answers 404 rather than 403, so this '
        + 'route cannot be used to discover which identifiers exist.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      response: {
        200: { ...clientView, description: 'The registration. No secret.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within this caller\'s reach.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const record = await findClient({ ...reach(caller, realm.realmId, 'view'), clientId });
    if (!record) return reply.status(404).send(problem(404, 'No such client'));

    return reply.send(view(record, caller));
  });

  fastify.post(base, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'registerClient',
      tags: ['oauth'],
      summary: 'Register an application',
      description:
        'Standard-defined: RFC 7591 dynamic client registration. The secret is generated here and '
        + 'returned once. Registration is self-service, and the registration belongs to the principal '
        + 'who created it. An ordinary owner is narrowed deliberately: sign-in scopes only, no '
        + 'client_credentials, redirect URIs that are absolute, HTTPS outside a loopback address, free '
        + 'of wildcards, and never on a host this platform already serves from.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm'],
        properties: { realm: { type: 'string', examples: ['acme'] } },
      },
      body: {
        type: 'object',
        required: ['client_name'],
        additionalProperties: true,
        properties: {
          client_name: { type: 'string', minLength: 1 },
          redirect_uris: { type: 'array', items: { type: 'string' } },
          post_logout_redirect_uris: { type: 'array', items: { type: 'string' } },
          grant_types: { type: 'array', items: { type: 'string' } },
          scope: { type: 'string' },
          logo_uri: { type: 'string' },
          /** The consumer's own record for whoever owns this client. Administrators only. */
          owner_ref: { type: 'string' },
        },
      },
      response: {
        201: { ...clientView, description: 'The registered client, with its secret, once.' },
        400: { $ref: 'Problem#', description: 'The registration asks for something self-service does not grant.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        403: { $ref: 'Problem#', description: 'The per-owner registration limit has been reached.' },
        404: { $ref: 'Problem#', description: 'No such realm.' },
        409: { $ref: 'Problem#', description: 'That client name is already registered here.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName } = request.params as { realm: string };
    const body = request.body as {
      client_name: string; redirect_uris?: string[]; post_logout_redirect_uris?: string[];
      grant_types?: string[]; scope?: string; logo_uri?: string; owner_ref?: string;
    };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    /** A refused registration, recorded before the answer goes back. */
    const refuse = (status: number, title: string, detail: string, cause: string) => {
      audit(realm, caller, {
        action: 'client.registered',
        outcome: 'failure',
        cause,
        detail: { clientName: body.client_name },
      });
      return reply.status(status as 400).send(problem(status, title, detail));
    };

    if (await clients().findOne(clientFilter({ realmId: realm.realmId, clientName: body.client_name }), { projection: { _id: 0, clientId: 1 } })) {
      return refuse(409, 'Already registered', 'That application name is already registered in this realm.', 'name_taken');
    }

    const privileged = administers(caller, 'manage');
    let redirectUris = body.redirect_uris ?? [];
    let grantTypes = (body.grant_types ?? []) as string[];
    let scopes = (body.scope ?? '').split(' ').filter(Boolean);

    if (!privileged) {
      // A brake rather than a boundary: enough registrations for an integration and its copies, few
      // enough that scripting the endpoint stops being worth anything.
      // Counts what this principal OWNS, shared or not, rather than what they created. Ownership is
      // what carries the authority, so it is what the brake has to count: otherwise being added to
      // other people's applications would be a way around it.
      const held = await clients().countDocuments(clientFilter({
        realmId: realm.realmId,
        ...ownedBy(caller.subjectId),
        status: { $ne: 'revoked' },
      }));
      if (held >= SELF_SERVICE_CLIENT_LIMIT) {
        return refuse(
          403,
          'Registration limit reached',
          `You already have ${held} applications registered, which is the limit. Withdraw one you no longer use.`,
          'registration_limit_reached',
        );
      }

      const grants = checkGrantTypes(grantTypes);
      if (isRefusal(grants)) return refuse(400, 'Not available to a self-registered application', grants.refused, 'grant_type_not_permitted');
      grantTypes = grants.grantTypes;

      const asked = checkScopes(scopes);
      if (isRefusal(asked)) return refuse(400, 'Not available to a self-registered application', asked.refused, 'scope_not_permitted');
      scopes = asked.scopes;

      const addresses = checkRedirectUris(redirectUris, await reservedHosts(realm.realmId, caller.subjectId));
      if (isRefusal(addresses)) return refuse(400, 'Redirect URI refused', addresses.refused, 'redirect_uri_refused');
      redirectUris = addresses.uris;
    }

    if (grantTypes.length === 0) grantTypes = ['client_credentials'];
    if (scopes.length === 0) scopes = ['openid'];

    const clientId = `cli-${randomUUID()}`;
    const { secret, hash, prefix } = await mintSecret();
    const isPublic = grantTypes.every((grant) => grant === 'authorization_code');

    /**
     * The owner set a registration starts with.
     *
     * The caller owns what they register, and an administrator may additionally name a consuming
     * application's own record. Both go in: an administrator who registers on somebody's behalf stays
     * able to administer it, which is what stops a registration being created that nobody but an
     * operator credential could ever touch.
     */
    const owners = [
      ...(caller.subjectId ? [{ kind: OWNER_KIND, ref: caller.subjectId }] : []),
      ...(privileged && body.owner_ref ? [{ kind: 'tenant', ref: body.owner_ref }] : []),
    ];
    if (owners.length === 0) {
      return refuse(
        400,
        'An owner is required',
        'The operator credential is nobody in particular, so it cannot own a registration. Name an '
        + 'owner reference, or register while signed in as the person who will administer it.',
        'no_owner',
      );
    }

    /**
     * The registration IS a credential, of type `oauth_client`.
     *
     * `ownerSubjectId` is the principal it acts as and answers for, which is a token subject and so
     * is singular. `administrators` is who may manage it, which is a set. The two are separate
     * fields because a `client_credentials` token has exactly one `sub`.
     */
    const credential: CredentialRecord = {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      credentialId: randomUUID(),
      // A credential belongs to the subject it authenticates, which for a client is the client.
      subjectId: clientId,
      type: 'oauth_client',
      ownerSubjectId: caller.subjectId ?? (body.owner_ref as string),
      administrators: owners as CredentialRecord['administrators'],
      clientId,
      ...(hash ? { secretHash: hash } : {}),
      ...(prefix ? { secretPrefix: prefix } : {}),
      metadata: clientMetadata({
        clientName: body.client_name,
        clientType: isPublic ? 'public' : 'confidential',
        redirectUris,
        postLogoutRedirectUris: body.post_logout_redirect_uris ?? [],
        grantTypes: grantTypes as OAuthClient['grantTypes'],
        scope: scopes.join(' '),
        ...(body.logo_uri ? { logoUri: body.logo_uri } : {}),
        requirePkce: true,
        tokenEndpointAuthMethod: isPublic ? 'none' : 'client_secret_basic',
        applicationType: 'web',
      }),
      status: 'active',
      assurance: { level: 'aal1', method: 'client_secret' },
      createdAt: new Date().toISOString(),
      meta: newMeta('Credential'),
    };

    await clients().insertOne(credential);
    const record = clientFromCredential(credential);

    audit(realm, caller, {
      action: 'client.registered',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      // An administrator may register on somebody's behalf, and that person is an owner from this
      // moment, so the registration of the thing they now administer belongs in their trail.
      stakeholderSubjectIds: ownerSubjects(record),
      detail: {
        clientName: body.client_name,
        owners: owners.map((owner) => owner.ref),
        selfService: !privileged,
      },
    });

    return reply.status(201).send({
      ...view(record, caller),
      // The one and only time this value leaves the authority.
      client_secret: secret,
    });
  });

  fastify.patch(`${base}/:clientId`, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'updateClient',
      tags: ['oauth'],
      summary: 'Change a registered application',
      description:
        'Standard-defined: RFC 7592 client configuration. Changes the registration; never returns or '
        + 'changes the secret, which has its own route so that rotating a credential is always a '
        + 'deliberate act rather than a side effect of editing a redirect URI. An owner may change '
        + 'their own; the whole realm needs the realm-wide permission.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: true,
        properties: {
          client_name: { type: 'string', minLength: 1 },
          redirect_uris: { type: 'array', items: { type: 'string' } },
          post_logout_redirect_uris: { type: 'array', items: { type: 'string' } },
          scope: { type: 'string' },
          logo_uri: { type: 'string' },
        },
      },
      response: {
        200: { ...clientView, description: 'The client, as changed. No secret.' },
        400: { $ref: 'Problem#', description: 'The change asks for something self-service does not grant.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within this caller\'s reach.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const body = request.body as {
      client_name?: string; redirect_uris?: string[]; post_logout_redirect_uris?: string[];
      scope?: string; logo_uri?: string;
    };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const existing = await findClient({ ...reach(caller, realm.realmId, 'manage'), clientId });
    if (!existing) return reply.status(404).send(problem(404, 'No such client'));

    const privileged = administers(caller, 'manage');
    const update: Record<string, unknown> = {};
    if (body.client_name) update.clientName = body.client_name;
    if (body.logo_uri) update.logoUri = body.logo_uri;

    if (body.scope !== undefined) {
      const scopes = body.scope.split(' ').filter(Boolean);
      if (!privileged) {
        const asked = checkScopes(scopes);
        if (isRefusal(asked)) return reply.status(400).send(problem(400, 'Not available to a self-registered application', asked.refused));
        update.scope = asked.scopes.join(' ');
      } else {
        update.scope = scopes.join(' ');
      }
    }

    for (const [field, value] of [['redirectUris', body.redirect_uris], ['postLogoutRedirectUris', body.post_logout_redirect_uris]] as const) {
      if (!value) continue;
      if (!privileged) {
        const checked = checkRedirectUris(value, await reservedHosts(realm.realmId, caller.subjectId));
        if (isRefusal(checked)) return reply.status(400).send(problem(400, 'Redirect URI refused', checked.refused));
        update[field] = checked.uris;
      } else {
        update[field] = value;
      }
    }

    await clients().updateOne(
      clientFilter({ realmId: realm.realmId, clientId }),
      { $set: { ...clientUpdate(update), 'meta.lastModified': new Date().toISOString() } },
    );

    audit(realm, caller, {
      action: 'client.updated',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient),
      detail: { changed: Object.keys(update) },
    });

    const updated = await findClient({ realmId: realm.realmId, clientId });
    return reply.send(view(updated as OAuthClient, caller));
  });

  fastify.post(`${base}/:clientId/rotate-secret`, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'rotateClientSecret',
      tags: ['oauth'],
      summary: 'Issue a new secret for an application',
      description:
        'Standard-adjacent: the credential half of RFC 7592. The previous secret stops working '
        + 'immediately. There is no overlap window, because two live secrets means a compromised one '
        + 'keeps working for the length of that window, which is exactly when it must not. Rotating '
        + 'somebody else\'s credential is a separate authority from reading their registration, and it '
        + 'takes its own permission.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      response: {
        200: { ...clientView, description: 'The client, with its new secret, once.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within this caller\'s reach.' },
        409: { $ref: 'Problem#', description: 'That registration is withdrawn, so it has no credential to rotate.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const existing = await findClient({ ...reach(caller, realm.realmId, 'rotateSecret'), clientId });
    if (!existing) return reply.status(404).send(problem(404, 'No such client'));
    if (existing.status === 'revoked') {
      audit(realm, caller, { action: 'client.secret_rotated', outcome: 'failure', cause: 'client_withdrawn', clientId });
      return reply.status(409).send(problem(409, 'Withdrawn', 'A withdrawn registration has no credential to rotate.'));
    }

    /**
     * Rotation ADDS a credential rather than replacing one.
     *
     * Both secrets are then active, so a deployment can take the new one and roll over at its own
     * pace instead of every instance failing between the write here and the redeploy there. That
     * overlap is the whole reason a client registration became a credential: one field could only
     * ever hold one secret, so rotating it was an instantaneous cutover nobody could stage.
     *
     * Capped at two, and the cap is enforced here because an index can express "exactly one" and
     * not "at most two". Retiring the old one is a separate, deliberate act.
     */
    const active = await clients().countDocuments(
      clientFilter({ realmId: realm.realmId, clientId, status: 'active' }),
    );
    if (!withinActiveSecretCap(active)) {
      audit(realm, caller, { action: 'client.secret_rotated', outcome: 'failure', cause: 'rotation_window_open', clientId });
      return reply.status(409).send(problem(
        409,
        'A rotation is already in progress',
        `That registration already has ${active} active secrets, which is the limit. Retire the `
        + 'superseded one before minting another, so a forgotten secret cannot stay valid forever.',
      ));
    }

    const { secret, hash, prefix } = await mintSecret();
    await clients().insertOne({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      credentialId: randomUUID(),
      subjectId: clientId,
      type: 'oauth_client',
      ownerSubjectId: caller.subjectId ?? clientId,
      ...(existing.owners ? { administrators: existing.owners } : {}),
      clientId,
      secretHash: hash,
      secretPrefix: prefix,
      // The same registration metadata: this is a second secret for one client, not a second client.
      metadata: clientMetadata(existing),
      status: 'active',
      assurance: { level: 'aal1', method: 'client_secret' },
      createdAt: new Date().toISOString(),
      meta: newMeta('Credential'),
    });

    audit(realm, caller, {
      action: 'client.secret_rotated',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      // Named for every owner, not only the one who asked: the rotation window is now open for all
      // of them, and the superseded secret still works until somebody retires it.
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient),
      detail: { secretPrefix: prefix, activeSecrets: active + 1 },
    });

    return reply.send({ ...view(existing as OAuthClient, caller), client_secret: secret });
  });

  fastify.delete(`${base}/:clientId`, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'revokeClient',
      tags: ['oauth'],
      summary: 'Withdraw an application',
      description:
        'Standard-defined: RFC 7592 deletion. The registration is marked revoked rather than removed, '
        + 'so an audit trail naming this client still resolves. Nothing it holds keeps working: the '
        + 'credential stops authenticating immediately.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      response: {
        // Answered with the withdrawn registration rather than an empty 204, so a caller can confirm
        // what it just withdrew without a second read.
        200: { ...clientView, description: 'The registration, now withdrawn.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within this caller\'s reach.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const existing = await findClient({ ...reach(caller, realm.realmId, 'manage'), clientId });
    if (!existing) return reply.status(404).send(problem(404, 'No such client'));

    // updateMany, not updateOne: a rotation window leaves TWO active credentials for one clientId,
    // and withdrawing a registration that revoked only the newer one would leave the superseded
    // secret working. That is the precise failure this had no way to have before rotation existed.
    await clients().updateMany(
      clientFilter({ realmId: realm.realmId, clientId }),
      {
        // The hash is dropped as well as the status changed. A revoked client whose secret is still
        // stored is a credential waiting for somebody to reactivate the record.
        $set: { status: 'revoked', 'meta.lastModified': new Date().toISOString() },
        $unset: { secretHash: '' },
      },
    );

    audit(realm, caller, {
      action: 'client.revoked',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient),
    });

    return reply.send({ ...view(existing as OAuthClient, caller), status: 'revoked' });
  });

  /**
   * Adding and removing an owner.
   *
   * Its own pair of routes rather than a field on the update, because changing who may administer an
   * application is a different act from changing what the application is, and it deserves its own
   * entry in the trail. Any owner may do it: there is no primary owner to ask.
   */
  const ownersBase = base + '/:clientId/owners';

  fastify.post(ownersBase, {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'addClientOwner',
      tags: ['oauth'],
      summary: 'Give somebody else authority over an application',
      description:
        'No applicable standard; RFC 7591 registers a client but says nothing about who administers '
        + 'one afterwards. The principal named here gains exactly the authority the caller already '
        + 'has over this registration: read it, change it, rotate its secret, withdraw it. There is no '
        + 'primary owner, because a hierarchy raises a question this authority cannot answer, namely '
        + 'what happens to the application when the primary leaves.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId'],
        properties: { realm: { type: 'string' }, clientId: { type: 'string' } },
      },
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          subject_id: { type: 'string', description: 'The principal, by subject identifier.' },
          user_name: { type: 'string', description: 'The same principal, by the exact user name the directory holds.' },
        },
      },
      response: {
        200: { ...clientView, description: 'The registration, with its owners as they now stand.' },
        400: { $ref: 'Problem#', description: 'Neither a subject identifier nor a user name was given.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within reach, or no such principal.' },
        409: { $ref: 'Problem#', description: 'That principal already owns this registration.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId } = request.params as { realm: string; clientId: string };
    const { subject_id: subjectId, user_name: userName } = request.body as { subject_id?: string; user_name?: string };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));
    if (!subjectId && !userName) {
      return reply.status(400).send(problem(400, 'Nobody named', 'Give either a subject identifier or a user name.'));
    }

    /** A refused ownership change, recorded against the caller and the registration they aimed at. */
    const refuseOwner = (status: number, title: string, detail: string, cause: string) => {
      audit(realm, caller, {
        action: 'client.owner_added',
        outcome: 'failure',
        cause,
        clientId,
        target: { type: 'client', ref: clientId },
      });
      return reply.status(status as 404).send(problem(status, title, detail));
    };

    const existing = await findClient({ ...reach(caller, realm.realmId, 'manage'), clientId });
    if (!existing) return refuseOwner(404, 'No such client', 'No such client', 'client_out_of_reach');

    // An exact lookup, never a search. Naming somebody you already know is not enumeration, and the
    // answer is the same shape whether the principal is absent or belongs to another realm.
    const directory = new DirectoryService(fastify.db);
    const identity = subjectId
      ? await directory.findBySubjectId(subjectId)
      : await directory.findByUserName(realm.realmId, userName as string);
    if (!identity || identity.realmId !== realm.realmId) {
      return refuseOwner(404, 'No such principal', 'No such principal', 'unknown_principal');
    }

    if (isOwner(existing as OAuthClient, identity.subjectId)) {
      return refuseOwner(409, 'Already an owner', 'That principal already administers this registration.', 'already_an_owner');
    }

    const displayName = identity.name?.formatted || identity.userName;
    const added = {
      kind: OWNER_KIND,
      ref: identity.subjectId,
      // Copied at the moment of the change, so the trail can name an owner without a directory read.
      ...(displayName ? { displayName } : {}),
    };
    await clients().updateOne(
      clientFilter({ realmId: realm.realmId, clientId }),
      { $addToSet: { administrators: added }, $set: { 'meta.lastModified': new Date().toISOString() } },
    );

    audit(realm, caller, {
      action: 'client.owner_added',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      // Everyone who already administers this registration, plus the person who now does. It changed
      // who may administer something they own, so it is their event as much as the caller's.
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient, identity.subjectId),
      detail: { owner: identity.subjectId, ownerName: displayName },
    });

    const updated = await findClient({ realmId: realm.realmId, clientId });
    return reply.send(view(updated as OAuthClient, caller));
  });

  fastify.delete(ownersBase + '/:ownerRef', {
    preHandler: requireAuthorityCaller,
    schema: {
      operationId: 'removeClientOwner',
      tags: ['oauth'],
      summary: 'Take authority over an application away',
      description:
        'No applicable standard; the other half of client ownership, which RFC 7591 does not model. '
        + 'Removing yourself is allowed while somebody else remains. Removing the LAST owner is '
        + 'refused: a registration nobody administers can only be reached again with an operator '
        + 'credential, which is a break-glass path and not a way to run a registry.',
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['realm', 'clientId', 'ownerRef'],
        properties: {
          realm: { type: 'string' },
          clientId: { type: 'string' },
          ownerRef: { type: 'string', description: 'The reference of the owner to remove, as listed on the registration.' },
        },
      },
      response: {
        200: { ...clientView, description: 'The registration, with its owners as they now stand.' },
        401: { $ref: 'Problem#', description: 'No valid access token and no operator credential.' },
        404: { $ref: 'Problem#', description: 'No such client within reach, or no such owner on it.' },
        409: { $ref: 'Problem#', description: 'That is the last owner, and a registration cannot have none.' },
      },
    },
  }, async (request, reply) => {
    const caller = request.authorityCaller!;
    const { realm: realmName, clientId, ownerRef } = request.params as { realm: string; clientId: string; ownerRef: string };

    const realm = await realmOf(realmName);
    if (!realm) return reply.status(404).send(problem(404, 'Unknown realm'));

    const existing = await findClient({ ...reach(caller, realm.realmId, 'manage'), clientId });
    if (!existing) return reply.status(404).send(problem(404, 'No such client'));

    const owners = (existing as OAuthClient).owners ?? [];
    const target = owners.find((owner) => owner.ref === ownerRef);
    const refuseRemoval = (cause: string) => audit(realm, caller, {
      action: 'client.owner_removed',
      outcome: 'failure',
      cause,
      clientId,
      target: { type: 'client', ref: clientId },
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient),
    });

    if (!target) {
      refuseRemoval('no_such_owner');
      return reply.status(404).send(problem(404, 'No such owner on this registration'));
    }
    if (owners.length <= 1) {
      refuseRemoval('last_owner');
      return reply.status(409).send(problem(
        409,
        'The last owner cannot be removed',
        'A registration with no owner can only be administered with the operator credential, which is '
        + 'a break-glass path. Add another owner first, then remove this one.',
      ));
    }

    await clients().updateOne(
      clientFilter({ realmId: realm.realmId, clientId }),
      { $pull: { administrators: { ref: ownerRef } }, $set: { 'meta.lastModified': new Date().toISOString() } },
    );

    audit(realm, caller, {
      action: 'client.owner_removed',
      outcome: 'success',
      clientId,
      target: { type: 'client', ref: clientId },
      // The owner set as it stood BEFORE the removal, so the person who lost the authority reads the
      // event that took it away. Afterwards they are no longer an owner and nothing would name them.
      stakeholderSubjectIds: ownerSubjects(existing as OAuthClient),
      detail: {
        owner: ownerRef,
        ownerName: target.displayName,
        // Giving up your own authority and taking away somebody else's read very differently to
        // whoever reviews the trail afterwards, so the record says which one this was.
        self: target.kind === OWNER_KIND && target.ref === caller.subjectId,
      },
    });

    const updated = await findClient({ realmId: realm.realmId, clientId });
    return reply.send(view(updated as OAuthClient, caller));
  });
}
