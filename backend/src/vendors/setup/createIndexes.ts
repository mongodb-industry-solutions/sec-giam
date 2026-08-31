import { Db, IndexSpecification, CreateIndexesOptions } from 'mongodb';
import {
  GIAM_COLLECTIONS,
  REALM_COLLECTION, IDENTITY_PROVIDER_COLLECTION, TENANT_COLLECTION,
  IDENTITY_COLLECTION, CREDENTIAL_COLLECTION, AGENT_COLLECTION, TOOL_COLLECTION, MCP_SERVER_COLLECTION,
  CLIENT_COLLECTION, API_KEY_COLLECTION, AUTHORIZATION_REQUEST_COLLECTION, TOKEN_COLLECTION,
  SIGNING_KEY_COLLECTION, RESOURCE_SERVER_COLLECTION, PERMISSION_COLLECTION, ROLE_COLLECTION,
  ROLE_ASSIGNMENT_COLLECTION, POLICY_COLLECTION, RELATIONSHIP_COLLECTION,
  SESSION_COLLECTION, GRANT_COLLECTION, DELEGATION_COLLECTION,
  COUNTERS_COLLECTION, IDEMPOTENCY_COLLECTION,
} from '../../shared/models/collections';

export interface IndexPlan {
  collection: string;
  keys: IndexSpecification;
  options: CreateIndexesOptions & { name: string };
}

/**
 * Every index GIAM declares, in one list so setup creates it and validation checks the same thing.
 *
 * Two rules shape the list. Uniqueness is always PER REALM, because two realms are two institutions
 * and a user name that collides across them is not a collision. And every compound index leads with
 * `{realmId, tenantId}`: that pair is the partition key and the shard key if this deployment ever
 * shards, and a shard key cannot be changed later without a migration.
 */
export function plannedIndexes(): IndexPlan[] {
  const plans: IndexPlan[] = [
    // Realm and federation.
    { collection: REALM_COLLECTION, keys: { realmId: 1 }, options: { name: 'realmId_unique', unique: true } },
    { collection: REALM_COLLECTION, keys: { name: 1 }, options: { name: 'name_unique', unique: true } },
    // Resolving an issuer URL back to its realm happens on every token verification path.
    { collection: REALM_COLLECTION, keys: { issuer: 1 }, options: { name: 'issuer_unique', unique: true } },
    // The wire alias a caller may use instead of the realm's own name.
    { collection: REALM_COLLECTION, keys: { aliases: 1 }, options: { name: 'aliases', sparse: true } },

    { collection: IDENTITY_PROVIDER_COLLECTION, keys: { providerId: 1 }, options: { name: 'providerId_unique', unique: true } },
    { collection: IDENTITY_PROVIDER_COLLECTION, keys: { realmId: 1, tenantId: 1, name: 1 }, options: { name: 'realm_tenant_name_unique', unique: true } },
    // Home-realm discovery resolves an entered email domain to a provider.
    { collection: IDENTITY_PROVIDER_COLLECTION, keys: { realmId: 1, 'config.emailDomains': 1 }, options: { name: 'realm_emailDomains', sparse: true } },

    // Unique per REALM, not globally. A tenant is a boundary inside a realm, so the pair is its
    // identity; a global unique would force every realm to prefix its tenant names and would make the
    // partition key redundant with itself.
    { collection: TENANT_COLLECTION, keys: { realmId: 1, tenantId: 1 }, options: { name: 'realm_tenantId_unique', unique: true } },
    { collection: TENANT_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },
    { collection: TENANT_COLLECTION, keys: { realmId: 1, parentTenantId: 1 }, options: { name: 'realm_parent', sparse: true } },

    // Directory.
    { collection: IDENTITY_COLLECTION, keys: { subjectId: 1 }, options: { name: 'subjectId_unique', unique: true } },
    { collection: IDENTITY_COLLECTION, keys: { realmId: 1, userName: 1 }, options: { name: 'realm_userName_unique', unique: true } },
    { collection: IDENTITY_COLLECTION, keys: { realmId: 1, tenantId: 1, kind: 1, lifecycleState: 1 }, options: { name: 'realm_tenant_kind_state' } },
    // SCIM correlation for inbound provisioning. Sparse: only a federated or provisioned record has one.
    { collection: IDENTITY_COLLECTION, keys: { realmId: 1, externalId: 1 }, options: { name: 'realm_externalId', sparse: true } },
    { collection: IDENTITY_COLLECTION, keys: { realmId: 1, providerId: 1 }, options: { name: 'realm_providerId', sparse: true } },
    // The blind digest, not the encrypted value: a keyed one-way digest can carry a unique index,
    // encrypted material cannot. Partial, because a workload has no phone number.
    {
      collection: IDENTITY_COLLECTION,
      keys: { realmId: 1, primaryPhoneDigest: 1 },
      options: { name: 'realm_phoneDigest_unique', unique: true, partialFilterExpression: { primaryPhoneDigest: { $type: 'string' } } },
    },
    { collection: IDENTITY_COLLECTION, keys: { realmId: 1, demoFeatured: 1 }, options: { name: 'realm_demoFeatured', sparse: true } },
    // The workload binding, when one is attested.
    { collection: IDENTITY_COLLECTION, keys: { 'workload.spiffeId': 1 }, options: { name: 'workload_spiffeId', sparse: true } },

    { collection: CREDENTIAL_COLLECTION, keys: { credentialId: 1 }, options: { name: 'credentialId_unique', unique: true } },
    // The authentication hot path: every factor a subject holds of a given type, active ones first.
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, subjectId: 1, type: 1, status: 1 }, options: { name: 'realm_subject_type_status' } },
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, expiresAt: 1 }, options: { name: 'realm_expiresAt', sparse: true } },

    { collection: AGENT_COLLECTION, keys: { agentId: 1 }, options: { name: 'agentId_unique', unique: true } },
    { collection: AGENT_COLLECTION, keys: { realmId: 1, name: 1, version: 1 }, options: { name: 'realm_name_version_unique', unique: true } },
    { collection: AGENT_COLLECTION, keys: { realmId: 1, tenantId: 1, lifecycleState: 1 }, options: { name: 'realm_tenant_state' } },
    { collection: AGENT_COLLECTION, keys: { subjectId: 1 }, options: { name: 'subjectId' } },

    { collection: TOOL_COLLECTION, keys: { toolId: 1 }, options: { name: 'toolId_unique', unique: true } },
    { collection: TOOL_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },

    { collection: MCP_SERVER_COLLECTION, keys: { mcpServerId: 1 }, options: { name: 'mcpServerId_unique', unique: true } },
    { collection: MCP_SERVER_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },

    // OAuth.
    { collection: CLIENT_COLLECTION, keys: { realmId: 1, clientId: 1 }, options: { name: 'realm_clientId_unique', unique: true } },
    { collection: CLIENT_COLLECTION, keys: { realmId: 1, tenantId: 1, status: 1 }, options: { name: 'realm_tenant_status' } },
    // Resolving a client from the record that owns it, in the consuming application.
    { collection: CLIENT_COLLECTION, keys: { realmId: 1, 'owner.kind': 1, 'owner.ref': 1 }, options: { name: 'realm_owner', sparse: true } },
    // RFC 8705: locating the client bound to a presented certificate.
    { collection: CLIENT_COLLECTION, keys: { 'mtls.certificateThumbprint': 1 }, options: { name: 'mtls_thumbprint', sparse: true } },

    { collection: API_KEY_COLLECTION, keys: { keyId: 1 }, options: { name: 'keyId_unique', unique: true } },
    { collection: API_KEY_COLLECTION, keys: { realmId: 1, 'owner.kind': 1, 'owner.ref': 1 }, options: { name: 'realm_owner' } },
    // No index on keyHash here: it is a QE equality field, and its index is the encrypted one.

    { collection: AUTHORIZATION_REQUEST_COLLECTION, keys: { requestId: 1 }, options: { name: 'requestId_unique', unique: true } },
    // The code is stored hashed, and looked up by that hash on redemption.
    { collection: AUTHORIZATION_REQUEST_COLLECTION, keys: { realmId: 1, codeHash: 1 }, options: { name: 'realm_codeHash', sparse: true } },
    { collection: AUTHORIZATION_REQUEST_COLLECTION, keys: { authReqId: 1 }, options: { name: 'authReqId', sparse: true } },
    { collection: AUTHORIZATION_REQUEST_COLLECTION, keys: { realmId: 1, subjectId: 1, status: 1 }, options: { name: 'realm_subject_status', sparse: true } },
    // Expiry is the database's job: a cleanup job is a thing that fails silently.
    { collection: AUTHORIZATION_REQUEST_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 } },

    { collection: TOKEN_COLLECTION, keys: { jti: 1 }, options: { name: 'jti_unique', unique: true } },
    { collection: TOKEN_COLLECTION, keys: { realmId: 1, subjectId: 1, type: 1 }, options: { name: 'realm_subject_type' } },
    { collection: TOKEN_COLLECTION, keys: { sessionId: 1 }, options: { name: 'sessionId', sparse: true } },
    // Revocation propagation reads the recently revoked, so it is indexed rather than scanned.
    { collection: TOKEN_COLLECTION, keys: { realmId: 1, revokedAt: -1 }, options: { name: 'realm_revokedAt', sparse: true } },
    {
      collection: TOKEN_COLLECTION,
      keys: { expiresAt: 1 },
      // A grace beyond expiry, so a replay of an expired token is still detectable rather than simply
      // absent. Detecting a replay is the point of keeping the record at all.
      options: { name: 'expiresAt_ttl', expireAfterSeconds: 86400 },
    },

    { collection: SIGNING_KEY_COLLECTION, keys: { kid: 1 }, options: { name: 'kid_unique', unique: true } },
    // The JWKS read: every key a realm still publishes, on every verification cold start.
    { collection: SIGNING_KEY_COLLECTION, keys: { realmId: 1, status: 1, notAfter: 1 }, options: { name: 'realm_status_notAfter' } },
    // Lease renewal, and finding the keys whose owning replica has gone away.
    { collection: SIGNING_KEY_COLLECTION, keys: { realmId: 1, instanceId: 1 }, options: { name: 'realm_instanceId', sparse: true } },
    { collection: SIGNING_KEY_COLLECTION, keys: { leaseExpiresAt: 1 }, options: { name: 'leaseExpiresAt', sparse: true } },

    // Authorization.
    { collection: RESOURCE_SERVER_COLLECTION, keys: { resourceServerId: 1 }, options: { name: 'resourceServerId_unique', unique: true } },
    { collection: RESOURCE_SERVER_COLLECTION, keys: { realmId: 1, audience: 1 }, options: { name: 'realm_audience_unique', unique: true } },

    { collection: PERMISSION_COLLECTION, keys: { permissionId: 1 }, options: { name: 'permissionId_unique', unique: true } },
    { collection: PERMISSION_COLLECTION, keys: { realmId: 1, resourceServerId: 1, resource: 1, action: 1 }, options: { name: 'realm_server_resource_action_unique', unique: true } },

    { collection: ROLE_COLLECTION, keys: { roleId: 1 }, options: { name: 'roleId_unique', unique: true } },
    { collection: ROLE_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },
    // Role composition is resolved with a graph lookup, which needs the parent edge indexed.
    { collection: ROLE_COLLECTION, keys: { realmId: 1, parentRoleIds: 1 }, options: { name: 'realm_parentRoleIds' } },

    { collection: ROLE_ASSIGNMENT_COLLECTION, keys: { assignmentId: 1 }, options: { name: 'assignmentId_unique', unique: true } },
    // The decision point's own query, and the reason the pair leads: resolve one subject's live roles.
    { collection: ROLE_ASSIGNMENT_COLLECTION, keys: { realmId: 1, subjectId: 1, expiresAt: 1 }, options: { name: 'realm_subject_expiresAt' } },
    { collection: ROLE_ASSIGNMENT_COLLECTION, keys: { realmId: 1, roleId: 1 }, options: { name: 'realm_roleId' } },
    // An elevation expires; a permanent assignment has no expiry and must not be swept.
    {
      collection: ROLE_ASSIGNMENT_COLLECTION,
      keys: { expiresAt: 1 },
      options: { name: 'expiresAt_ttl', expireAfterSeconds: 0, partialFilterExpression: { ephemeral: true } },
    },

    { collection: POLICY_COLLECTION, keys: { policyId: 1 }, options: { name: 'policyId_unique', unique: true } },
    { collection: POLICY_COLLECTION, keys: { realmId: 1, tenantId: 1, enabled: 1 }, options: { name: 'realm_tenant_enabled' } },
    { collection: POLICY_COLLECTION, keys: { realmId: 1, attachedTo: 1 }, options: { name: 'realm_attachedTo' } },

    // Both directions: "what does this subject relate to" and "who relates to this object".
    { collection: RELATIONSHIP_COLLECTION, keys: { relationshipId: 1 }, options: { name: 'relationshipId_unique', unique: true } },
    { collection: RELATIONSHIP_COLLECTION, keys: { realmId: 1, subjectRef: 1, relation: 1 }, options: { name: 'realm_subject_relation' } },
    { collection: RELATIONSHIP_COLLECTION, keys: { realmId: 1, objectRef: 1, relation: 1 }, options: { name: 'realm_object_relation' } },
    { collection: RELATIONSHIP_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0, sparse: true } },

    // Sessions and consent.
    { collection: SESSION_COLLECTION, keys: { sessionId: 1 }, options: { name: 'sessionId_unique', unique: true } },
    { collection: SESSION_COLLECTION, keys: { realmId: 1, subjectId: 1, terminatedAt: 1 }, options: { name: 'realm_subject_terminated' } },
    { collection: SESSION_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 } },

    { collection: GRANT_COLLECTION, keys: { grantId: 1 }, options: { name: 'grantId_unique', unique: true } },
    // One live grant per subject and client; a revoked one stays as evidence, so the index is partial.
    {
      collection: GRANT_COLLECTION,
      keys: { realmId: 1, subjectId: 1, clientId: 1 },
      options: { name: 'realm_subject_client_active_unique', unique: true, partialFilterExpression: { status: 'active' } },
    },
    { collection: GRANT_COLLECTION, keys: { realmId: 1, clientId: 1 }, options: { name: 'realm_clientId' } },

    { collection: DELEGATION_COLLECTION, keys: { delegationId: 1 }, options: { name: 'delegationId_unique', unique: true } },
    { collection: DELEGATION_COLLECTION, keys: { realmId: 1, principalSubjectId: 1, agentId: 1, expiresAt: 1 }, options: { name: 'realm_principal_agent_expiresAt' } },
    { collection: DELEGATION_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0, sparse: true } },

    // Infrastructure.
    { collection: COUNTERS_COLLECTION, keys: { _id: 1 }, options: { name: '_id_' } },
    { collection: IDEMPOTENCY_COLLECTION, keys: { key: 1 }, options: { name: 'key_unique', unique: true } },
    { collection: IDEMPOTENCY_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 } },
  ];

  return plans;
}

export async function createIndexes(db: Db): Promise<void> {
  const existing = new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));

  for (const plan of plannedIndexes()) {
    if (!existing.has(plan.collection)) {
      console.log(`  skip:    ${plan.collection}.${plan.options.name} (collection missing)`);
      continue;
    }
    // _id is created by the server; asking for it again is an error on some deployments.
    if (plan.options.name === '_id_') continue;
    try {
      await db.collection(plan.collection).createIndex(plan.keys, plan.options);
      console.log(`  index:   ${plan.collection}.${plan.options.name}`);
    } catch (err) {
      // An index that already exists with different options is a real disagreement, not noise: it
      // means the declared plan and the database have drifted, and silence would hide it.
      const reason = err instanceof Error ? err.message : String(err);
      console.error(`  FAILED:  ${plan.collection}.${plan.options.name}: ${reason}`);
      throw err;
    }
  }

  const planned = new Set(plannedIndexes().map((p) => p.collection));
  const unindexed = GIAM_COLLECTIONS
    .filter((spec) => spec.kind !== 'timeseries' && !planned.has(spec.name))
    .map((spec) => spec.name);
  if (unindexed.length > 0) {
    console.log(`  note:    no declared index on: ${unindexed.join(', ')}`);
  }
}
