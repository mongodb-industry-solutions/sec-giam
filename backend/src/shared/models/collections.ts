import { DOMAIN_EVENT_COLLECTION } from '@leafypay/eventbus';

/**
 * The canonical registry of every collection in the GIAM database, with the module that owns it.
 *
 * One list rather than a constant per file, because three separate mechanisms need exactly this list
 * and must never disagree: setup creates from it, validateSetup checks against it, and the day-one
 * invariant test asserts the partition key on it. A collection that exists and is absent here is an
 * undocumented ownership, and the test says so rather than a reviewer noticing.
 */

export type CollectionKind = 'standard' | 'timeseries' | 'infrastructure';

export interface CollectionSpec {
  name: string;
  /** The module folder under `src/modules/` that owns writes to it. */
  module: string;
  purpose: string;
  /**
   * Carries `realmId` and `tenantId`, and every compound index on it leads with the pair.
   * False only for infrastructure that is not domain data (counters, idempotency, the event store).
   */
  scoped: boolean;
  kind: CollectionKind;
  /** Holds Queryable Encryption fields, so it must be created WITH its encryptedFields map. */
  encrypted?: boolean;
  /** The field a TTL index expires on, when the collection is ephemeral by design. */
  ttlField?: string;
}

// Realm and federation.
export const REALM_COLLECTION = 'realm';
export const IDENTITY_PROVIDER_COLLECTION = 'identityProvider';
export const TENANT_COLLECTION = 'tenant';

// Directory: principals of every kind, and their credentials.
export const IDENTITY_COLLECTION = 'identity';
export const CREDENTIAL_COLLECTION = 'credential';
export const AGENT_COLLECTION = 'agent';
export const TOOL_COLLECTION = 'tool';
export const MCP_SERVER_COLLECTION = 'mcpServer';

// OAuth: clients, pending authorizations, issued tokens, keys.
export const CLIENT_COLLECTION = 'client';
export const API_KEY_COLLECTION = 'apiKey';
export const AUTHORIZATION_REQUEST_COLLECTION = 'authorizationRequest';
export const TOKEN_COLLECTION = 'token';
export const SIGNING_KEY_COLLECTION = 'signingKey';

// Authorization: what a resource server declares and what GIAM grants.
export const RESOURCE_SERVER_COLLECTION = 'resourceServer';
export const PERMISSION_COLLECTION = 'permission';
export const ROLE_COLLECTION = 'role';
export const ROLE_ASSIGNMENT_COLLECTION = 'roleAssignment';
export const POLICY_COLLECTION = 'policy';
export const RELATIONSHIP_COLLECTION = 'relationship';

// Authentication and consent.
export const SESSION_COLLECTION = 'session';
export const GRANT_COLLECTION = 'grant';
export const DELEGATION_COLLECTION = 'delegation';

// Audit.
export const SECURITY_EVENT_COLLECTION = 'securityEvent';

// Infrastructure, own instances.
export const COUNTERS_COLLECTION = 'counters';
export const IDEMPOTENCY_COLLECTION = 'idempotencyKey';

export const GIAM_COLLECTIONS: CollectionSpec[] = [
  {
    name: REALM_COLLECTION,
    module: 'realm',
    purpose: 'trust and key boundary: issuer, token policy, password policy, branding, registration',
    scoped: true,
    kind: 'standard',
  },
  {
    name: IDENTITY_PROVIDER_COLLECTION,
    module: 'realm',
    purpose: 'upstream federation inside a realm: protocol, config, claim mappings',
    scoped: true,
    kind: 'standard',
  },
  {
    name: TENANT_COLLECTION,
    module: 'directory',
    purpose: 'data boundary inside a realm, so one realm can serve many customers',
    scoped: true,
    kind: 'standard',
  },
  {
    name: IDENTITY_COLLECTION,
    module: 'directory',
    // The one principal record. A person and a workload are the same kind of record on purpose.
    purpose: 'every principal: human, workload, agent, application, service',
    scoped: true,
    kind: 'standard',
    encrypted: true,
  },
  {
    name: CREDENTIAL_COLLECTION,
    module: 'directory',
    purpose: 'every authentication factor, discriminated by type, with its assurance level',
    scoped: true,
    kind: 'standard',
  },
  {
    name: AGENT_COLLECTION,
    module: 'directory',
    // Distinct from a workload on purpose: one approved agent has many runtimes over its life.
    purpose: 'the logical agent definition: owner, purpose, configuration digest, allowed tools',
    scoped: true,
    kind: 'standard',
  },
  {
    name: TOOL_COLLECTION,
    module: 'directory',
    purpose: 'a callable capability exposed to agents, with normalized action names',
    scoped: true,
    kind: 'standard',
  },
  {
    name: MCP_SERVER_COLLECTION,
    module: 'directory',
    purpose: 'a Model Context Protocol tool or context server and the tools it exposes',
    scoped: true,
    kind: 'standard',
  },
  {
    name: CLIENT_COLLECTION,
    module: 'oauth',
    purpose: 'the OAuth client registry: credentials, redirect URIs, grants, scope, token policy',
    scoped: true,
    kind: 'standard',
  },
  {
    name: API_KEY_COLLECTION,
    module: 'oauth',
    purpose: 'integration keys by hash, never an agent identity',
    scoped: true,
    kind: 'standard',
    encrypted: true,
  },
  {
    name: AUTHORIZATION_REQUEST_COLLECTION,
    module: 'oauth',
    // One collection because an authorization code and a backchannel request are the same thing:
    // a short-lived pending authorization awaiting a user action.
    purpose: 'pending authorizations: authorization code and backchannel, one TTL for both',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: TOKEN_COLLECTION,
    module: 'oauth',
    purpose: 'issued and revoked tokens by jti, with the delegation chain that produced them',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: SIGNING_KEY_COLLECTION,
    module: 'keys',
    // Public material and a reference only. An unwrapped private PEM here is a compromise.
    purpose: 'the published key set per realm: public material, custody mode, lease, publication grace',
    scoped: true,
    kind: 'standard',
  },
  {
    name: RESOURCE_SERVER_COLLECTION,
    module: 'authorization',
    purpose: 'a protected application, its audience, its catalog version and its validation mode',
    scoped: true,
    kind: 'standard',
  },
  {
    name: PERMISSION_COLLECTION,
    module: 'authorization',
    purpose: 'the enforcement points a resource server declares in its own code',
    scoped: true,
    kind: 'standard',
  },
  {
    name: ROLE_COLLECTION,
    module: 'authorization',
    purpose: 'named permission sets, composable through parent roles',
    scoped: true,
    kind: 'standard',
  },
  {
    name: ROLE_ASSIGNMENT_COLLECTION,
    module: 'authorization',
    // A permanent role has no expiry; an elevation has one, which is what replaces an escalation token.
    purpose: 'subject times role, and the vehicle for time-bound privilege elevation',
    scoped: true,
    kind: 'standard',
  },
  {
    name: POLICY_COLLECTION,
    module: 'authorization',
    // Identity context only. A condition naming an amount or a business threshold is a defect.
    purpose: 'conditional statements evaluated after roles, deny wins',
    scoped: true,
    kind: 'standard',
  },
  {
    name: RELATIONSHIP_COLLECTION,
    module: 'authorization',
    purpose: 'relationship-based access control, resolved transitively',
    scoped: true,
    kind: 'standard',
  },
  {
    name: SESSION_COLLECTION,
    module: 'authentication',
    purpose: 'the platform session, so single logout and session listing are possible',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: GRANT_COLLECTION,
    module: 'consent',
    purpose: 'a principal consenting to a client\'s scopes',
    scoped: true,
    kind: 'standard',
  },
  {
    name: DELEGATION_COLLECTION,
    module: 'consent',
    // Not a grant: a human authorising an agent to act carries purpose, constraints and an expiry.
    purpose: 'a principal authorising an agent to act on their behalf, purpose bound and revocable',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: SECURITY_EVENT_COLLECTION,
    module: 'audit',
    purpose: 'append-only authentication, authorization, token and delegation evidence',
    scoped: true,
    kind: 'timeseries',
  },
  {
    name: DOMAIN_EVENT_COLLECTION,
    module: 'system',
    purpose: 'GIAM\'s own domain event store',
    scoped: false,
    kind: 'infrastructure',
  },
  {
    name: COUNTERS_COLLECTION,
    module: 'system',
    purpose: 'sequence counters, own instance',
    scoped: false,
    kind: 'infrastructure',
  },
  {
    name: IDEMPOTENCY_COLLECTION,
    module: 'system',
    purpose: 'idempotency keys, own instance',
    scoped: false,
    kind: 'infrastructure',
  },
];

export function collectionSpec(name: string): CollectionSpec | undefined {
  return GIAM_COLLECTIONS.find((spec) => spec.name === name);
}

export function scopedCollections(): CollectionSpec[] {
  return GIAM_COLLECTIONS.filter((spec) => spec.scoped);
}

export function encryptedCollections(): CollectionSpec[] {
  return GIAM_COLLECTIONS.filter((spec) => spec.encrypted);
}
