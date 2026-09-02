import { EVENTBUS_COLLECTION } from '@leafypay/eventbus';
import { RETIRED_CLIENT_FIELDS } from '../../modules/oauth/models/client.model';

/**
 * The canonical registry of every collection in the GIAM database, with the module that owns it.
 *
 * One list rather than a constant per file, because three separate mechanisms need exactly this list
 * and must never disagree: setup creates from it, validateSetup checks against it, and the day-one
 * invariant test asserts the partition key on it. A collection that exists and is absent here is an
 * undocumented ownership, and the test says so rather than a reviewer noticing.
 *
 * Thirteen collections, per ADR-001. The boundary that decided each merge: a flow is transient and
 * is discarded, a fact is durable and is kept. Nothing is stored that can be derived, so there are
 * no issued tokens, no revocation entries, no duplicated permissions and no second level of
 * organisation.
 */

export type CollectionKind = 'standard' | 'timeseries' | 'infrastructure';

export interface CollectionSpec {
  name: string;
  /** The module folder under `src/modules/` that owns writes to it. */
  module: string;
  purpose: string;
  /**
   * Carries `realmId` and `tenantId`, and every compound index on it leads with the pair.
   * False only for infrastructure that is not domain data, such as the event store.
   */
  scoped: boolean;
  kind: CollectionKind;
  /** Holds Queryable Encryption fields, so it must be created WITH its encryptedFields map. */
  encrypted?: boolean;
  /** The field a TTL index expires on, when the collection is ephemeral by design. */
  ttlField?: string;
  /** Fields no longer declared: the seeder unsets them, validation reports any that survive. */
  retiredFields?: readonly string[];
}

// Realm and the authentication paths into it.
export const REALM_COLLECTION = 'realm';
export const DOMAIN_COLLECTION = 'domain';

// Directory: every subject that acts, and everything that identifies one.
export const PRINCIPAL_COLLECTION = 'principal';
export const CREDENTIAL_COLLECTION = 'credential';

// OAuth: pending authorizations and the published key set.
export const AUTH_REQUEST_COLLECTION = 'authRequest';
export const KEY_COLLECTION = 'key';

// Authorization: what a resource declares and what GIAM grants over it.
export const RESOURCE_COLLECTION = 'resource';
export const ROLE_COLLECTION = 'role';
export const POLICY_COLLECTION = 'policy';

// Authentication and consent.
export const SESSION_COLLECTION = 'session';
export const GRANT_COLLECTION = 'grant';

// Audit.
export const AUDIT_COLLECTION = 'audit';

export { EVENTBUS_COLLECTION };

/**
 * Collections the target model absorbs, still named by code that has not been merged yet.
 *
 * Deliberately NOT in `GIAM_COLLECTIONS`: the registry states the target, so setup stops creating
 * them and validation reports them as unknown. These constants exist only so the compiler stays
 * usable between P1 and P7, and each is deleted by the phase that absorbs it. If one survives past
 * its phase, that is an unmerged write path and P11.6 fails on it.
 */

export const GIAM_COLLECTIONS: CollectionSpec[] = [
  {
    name: PRINCIPAL_COLLECTION,
    module: 'directory',
    // Every subject that acts, on purpose: a person, a workload, an agent and a service are the
    // same kind of record. Roles are embedded because issuing a token is the hottest read in the
    // system and embedded makes it one.
    purpose: 'every subject that acts: person, workload, agent, service, with its roles embedded',
    scoped: true,
    kind: 'standard',
    encrypted: true,
  },
  {
    name: CREDENTIAL_COLLECTION,
    module: 'directory',
    // A client_id plus client_secret authenticates a party to this server, which is structurally a
    // username plus password, so an OAuth client registration is a credential and not its own kind.
    purpose: 'everything that identifies a principal: password, MFA, API key, certificate, OAuth client',
    scoped: true,
    kind: 'standard',
    retiredFields: RETIRED_CLIENT_FIELDS,
  },
  {
    name: REALM_COLLECTION,
    module: 'realm',
    purpose: 'issuance boundary: issuer, key references, token lifetimes, branding, registration',
    scoped: true,
    kind: 'standard',
  },
  {
    name: DOMAIN_COLLECTION,
    module: 'realm',
    // One configured way to authenticate into a realm. The local directory is one domain among
    // others rather than a special case, which is what lets GIAM sit in front of an upstream.
    purpose: 'one authentication path into a realm, local or federated, with its session policy',
    scoped: true,
    kind: 'standard',
  },
  {
    name: KEY_COLLECTION,
    module: 'keys',
    // Public material and a reference only. An unwrapped private PEM here is a compromise.
    purpose: 'the published key set per realm: public material, custody mode, lease, publication grace',
    scoped: true,
    kind: 'standard',
  },
  {
    name: ROLE_COLLECTION,
    module: 'authorization',
    purpose: 'a named bundle of permissions, composable through parent roles',
    scoped: true,
    kind: 'standard',
  },
  {
    name: POLICY_COLLECTION,
    module: 'authorization',
    // Identity context only. A condition naming an amount or a business threshold is a defect.
    purpose: 'permissions over a resource under conditions, with an effect. Deny by default',
    scoped: true,
    kind: 'standard',
  },
  {
    name: RESOURCE_COLLECTION,
    module: 'authorization',
    // A tool and an API are the same kind of protected object, so an agent calling a tool goes
    // through the same decision function as a person reading an account. One engine, no special case.
    purpose: 'every protected object and the action catalog it declares, including tools and servers',
    scoped: true,
    kind: 'standard',
  },
  {
    name: SESSION_COLLECTION,
    module: 'authentication',
    // Active sessions only: the ABSENCE of the document is the revocation signal, which needs
    // nothing compared and no entry kept alive until the last affected token expires.
    purpose: 'the fact that access is still live, and the generation that detects a refresh replay',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: AUTH_REQUEST_COLLECTION,
    module: 'oauth',
    // The one place state must be written: an authorization code is a claim ticket handed over in
    // one channel and redeemed in another, so the PKCE challenge has to be remembered to be compared.
    purpose: 'a pending authorization awaiting a user action, seconds to minutes, TTL bounded',
    scoped: true,
    kind: 'standard',
    ttlField: 'expiresAt',
  },
  {
    name: GRANT_COLLECTION,
    module: 'consent',
    // A delegation is a grant with a purpose, not a separate concept.
    purpose: 'a subject consenting, optionally purpose bound and constrained',
    scoped: true,
    kind: 'standard',
  },
  {
    name: AUDIT_COLLECTION,
    module: 'audit',
    // Evidence, not plumbing and not application logs. A collection named for logs accumulates
    // stdout within a year, and then regulatory evidence lives mixed with noise.
    purpose: 'append-only authentication, authorization, token and consent evidence, long retention',
    scoped: true,
    kind: 'timeseries',
  },
  {
    name: EVENTBUS_COLLECTION,
    module: 'system',
    // Not merged with audit: it needs idempotency by eventId, which needs a unique index, and a
    // time series collection does not support one.
    purpose: 'the durable trail behind the event bus: fan out, deduplication, replay',
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

export function collectionsWithRetiredFields(): CollectionSpec[] {
  return GIAM_COLLECTIONS.filter((spec) => (spec.retiredFields?.length ?? 0) > 0);
}
