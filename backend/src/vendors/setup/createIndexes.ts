import { Db, IndexSpecification, CreateIndexesOptions } from 'mongodb';
import {
  GIAM_COLLECTIONS, collectionSpec,
  REALM_COLLECTION, DOMAIN_COLLECTION,
  PRINCIPAL_COLLECTION, CREDENTIAL_COLLECTION, TOOL_COLLECTION, MCP_SERVER_COLLECTION,
  AUTH_REQUEST_COLLECTION, TOKEN_COLLECTION,
  KEY_COLLECTION, RESOURCE_SERVER_COLLECTION, PERMISSION_COLLECTION, ROLE_COLLECTION,
  POLICY_COLLECTION,
  SESSION_COLLECTION, GRANT_COLLECTION, DELEGATION_COLLECTION,
  AUDIT_COLLECTION,
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

    { collection: DOMAIN_COLLECTION, keys: { providerId: 1 }, options: { name: 'providerId_unique', unique: true } },
    { collection: DOMAIN_COLLECTION, keys: { realmId: 1, tenantId: 1, name: 1 }, options: { name: 'realm_tenant_name_unique', unique: true } },
    // Home-realm discovery resolves an entered email domain to a provider.
    { collection: DOMAIN_COLLECTION, keys: { realmId: 1, 'config.emailDomains': 1 }, options: { name: 'realm_emailDomains', sparse: true } },

    // Directory.
    { collection: PRINCIPAL_COLLECTION, keys: { subjectId: 1 }, options: { name: 'subjectId_unique', unique: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, userName: 1 }, options: { name: 'realm_userName_unique', unique: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, tenantId: 1, kind: 1, lifecycleState: 1 }, options: { name: 'realm_tenant_kind_state' } },
    // SCIM correlation for inbound provisioning. Sparse: only a federated or provisioned record has one.
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, externalId: 1 }, options: { name: 'realm_externalId', sparse: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, providerId: 1 }, options: { name: 'realm_providerId', sparse: true } },
    // The blind digest, not the encrypted value: a keyed one-way digest can carry a unique index,
    // encrypted material cannot. Partial, because a workload has no phone number.
    {
      collection: PRINCIPAL_COLLECTION,
      keys: { realmId: 1, primaryPhoneDigest: 1 },
      options: { name: 'realm_phoneDigest_unique', unique: true, partialFilterExpression: { primaryPhoneDigest: { $type: 'string' } } },
    },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, demoFeatured: 1 }, options: { name: 'realm_demoFeatured', sparse: true } },
    // The workload binding, when one is attested.
    { collection: PRINCIPAL_COLLECTION, keys: { 'workload.spiffeId': 1 }, options: { name: 'workload_spiffeId', sparse: true } },
    // The inverse question: "who holds role X". Needed for access certification and for role
    // revocation, and multikey because the roles are embedded. Without it, both scan the realm.
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, 'roles.roleId': 1 }, options: { name: 'realm_roles_roleId' } },
    // Elevations in force, and the sweep that removes lapsed entries.
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, 'roles.ephemeral': 1 }, options: { name: 'realm_roles_ephemeral', sparse: true } },

    { collection: CREDENTIAL_COLLECTION, keys: { credentialId: 1 }, options: { name: 'credentialId_unique', unique: true } },
    // The authentication hot path: every factor a subject holds of a given type, active ones first.
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, subjectId: 1, type: 1, status: 1 }, options: { name: 'realm_subject_type_status' } },
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, expiresAt: 1 }, options: { name: 'realm_expiresAt', sparse: true } },
    /**
     * The client authentication hot path. NOT unique on {realmId, clientId}, deliberately.
     *
     * Rotating a secret with an overlap window means two active credentials share one clientId, so a
     * unique index there would make the overlap impossible and rotation would be back to a single
     * field swapped instantaneously. Uniqueness lives on credentialId, which is global above, and
     * the "at most two active" rule is enforced in the service, because an index can only express
     * "exactly one".
     */
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, clientId: 1, status: 1 }, options: { name: 'realm_clientId_status', sparse: true } },
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, type: 1 }, options: { name: 'realm_type' } },
    // Which registrations a principal administers, for the self-service listing and its limit.
    { collection: CREDENTIAL_COLLECTION, keys: { realmId: 1, 'administrators.kind': 1, 'administrators.ref': 1 }, options: { name: 'realm_administrators', sparse: true } },
    { collection: CREDENTIAL_COLLECTION, keys: { ownerSubjectId: 1 }, options: { name: 'ownerSubjectId', sparse: true } },
    // RFC 8705: locating the credential bound to a presented certificate.
    { collection: CREDENTIAL_COLLECTION, keys: { 'metadata.mtls.certificateThumbprint': 1 }, options: { name: 'mtls_thumbprint', sparse: true } },

    { collection: TOOL_COLLECTION, keys: { toolId: 1 }, options: { name: 'toolId_unique', unique: true } },
    { collection: TOOL_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },

    { collection: MCP_SERVER_COLLECTION, keys: { mcpServerId: 1 }, options: { name: 'mcpServerId_unique', unique: true } },
    { collection: MCP_SERVER_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },

    // OAuth.
    // Resolving a client from a record that owns it. Multikey, because ownership is a set: this is
    // the membership test every read on the registry narrows by, so it is not an optional index.
    // RFC 8705: locating the client bound to a presented certificate.

    // No index on keyHash here: it is a QE equality field, and its index is the encrypted one.

    { collection: AUTH_REQUEST_COLLECTION, keys: { requestId: 1 }, options: { name: 'requestId_unique', unique: true } },
    // The code is stored hashed, and looked up by that hash on redemption.
    { collection: AUTH_REQUEST_COLLECTION, keys: { realmId: 1, codeHash: 1 }, options: { name: 'realm_codeHash', sparse: true } },
    { collection: AUTH_REQUEST_COLLECTION, keys: { authReqId: 1 }, options: { name: 'authReqId', sparse: true } },
    { collection: AUTH_REQUEST_COLLECTION, keys: { realmId: 1, subjectId: 1, status: 1 }, options: { name: 'realm_subject_status', sparse: true } },
    // Expiry is the database's job: a cleanup job is a thing that fails silently.
    { collection: AUTH_REQUEST_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 } },

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

    { collection: KEY_COLLECTION, keys: { kid: 1 }, options: { name: 'kid_unique', unique: true } },
    // The JWKS read: every key a realm still publishes, on every verification cold start.
    { collection: KEY_COLLECTION, keys: { realmId: 1, status: 1, notAfter: 1 }, options: { name: 'realm_status_notAfter' } },
    // Lease renewal, and finding the keys whose owning replica has gone away.
    { collection: KEY_COLLECTION, keys: { realmId: 1, instanceId: 1 }, options: { name: 'realm_instanceId', sparse: true } },
    { collection: KEY_COLLECTION, keys: { leaseExpiresAt: 1 }, options: { name: 'leaseExpiresAt', sparse: true } },

    // Authorization.
    { collection: RESOURCE_SERVER_COLLECTION, keys: { resourceServerId: 1 }, options: { name: 'resourceServerId_unique', unique: true } },
    { collection: RESOURCE_SERVER_COLLECTION, keys: { realmId: 1, audience: 1 }, options: { name: 'realm_audience_unique', unique: true } },

    { collection: PERMISSION_COLLECTION, keys: { permissionId: 1 }, options: { name: 'permissionId_unique', unique: true } },
    { collection: PERMISSION_COLLECTION, keys: { realmId: 1, resourceServerId: 1, resource: 1, action: 1 }, options: { name: 'realm_server_resource_action_unique', unique: true } },

    { collection: ROLE_COLLECTION, keys: { roleId: 1 }, options: { name: 'roleId_unique', unique: true } },
    { collection: ROLE_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },
    // Role composition is resolved with a graph lookup, which needs the parent edge indexed.
    { collection: ROLE_COLLECTION, keys: { realmId: 1, parentRoleIds: 1 }, options: { name: 'realm_parentRoleIds' } },

    // No TTL index for an expired role holding, deliberately. A TTL index expires whole DOCUMENTS
    // and never array elements, so declaring one here would delete the principal rather than the
    // lapsed entry. Expiry is enforced by filtering at read time, which is the correctness
    // mechanism, plus the sweeper in `RoleAdminService.sweepExpiredHoldings` for hygiene.

    { collection: POLICY_COLLECTION, keys: { policyId: 1 }, options: { name: 'policyId_unique', unique: true } },
    // A decision names the policy that decided it as `name@version`, so two policies sharing a name
    // in one realm would make that record ambiguous exactly when it is being read as evidence.
    { collection: POLICY_COLLECTION, keys: { realmId: 1, name: 1 }, options: { name: 'realm_name_unique', unique: true } },
    { collection: POLICY_COLLECTION, keys: { realmId: 1, tenantId: 1, enabled: 1 }, options: { name: 'realm_tenant_enabled' } },
    { collection: POLICY_COLLECTION, keys: { realmId: 1, attachedTo: 1 }, options: { name: 'realm_attachedTo' } },

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

    // Audit. The trail is a time series, so the time field and the meta field are already organised
    // by the storage engine; this is the one query neither of them answers, namely "events that named
    // this person as a stakeholder". Without it the self-scoped narrowing degrades into a scan.
    // Realm first like every other compound index here, and neither sparse nor partial: a time series
    // index does not take those options, and the realm key would defeat sparseness anyway because
    // every event has one.
    {
      collection: AUDIT_COLLECTION,
      keys: { realmId: 1, stakeholderSubjectIds: 1, ts: -1 },
      options: { name: 'realm_stakeholders_ts' },
    },
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

  await reconcileIndexes(db, existing);
}

// A time series is left out entirely: its buckets and its default meta index belong to the engine.
export function reconcilable(collection: string): boolean {
  return collectionSpec(collection)?.kind !== 'timeseries';
}

/** What reconciliation concluded about one index that exists in the database. */
export type IndexVerdict = 'planned' | 'obsolete' | 'engine' | 'unrecognised';

export interface ExistingIndex {
  name?: string;
  key?: Record<string, unknown>;
  weights?: unknown;
  textIndexVersion?: unknown;
  '2dsphereIndexVersion'?: unknown;
}

// Only an index whose every key is an ordinary field path on a plan-managed collection is provably
// obsolete; anything else is kept, since dropping a driver-managed index would break encryption.
export function classifyIndex(
  index: ExistingIndex,
  plannedNames: Set<string>,
  collectionIsPlanned: boolean,
): IndexVerdict {
  const name = index.name ?? '';
  if (name === '_id_') return 'planned';
  if (plannedNames.has(name)) return 'planned';
  if (!collectionIsPlanned) return 'unrecognised';
  // A text or geo index is nothing this plan declares, so nothing here can judge it.
  if (index.weights || index.textIndexVersion || index['2dsphereIndexVersion']) return 'unrecognised';
  const keys = Object.keys(index.key ?? {});
  if (keys.length === 0) return 'unrecognised';
  // The Queryable Encryption safe-content array: the driver's own, and dropping it breaks encryption.
  if (keys.some((key) => key.startsWith('__'))) return 'engine';
  if (keys.some((key) => key.startsWith('$'))) return 'unrecognised';
  return 'obsolete';
}

// Drops the indexes no longer declared, so a rename does not leave the old one behind forever.
export async function reconcileIndexes(db: Db, existing?: Set<string>): Promise<void> {
  const present = existing
    ?? new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));

  const plans = plannedIndexes();
  const namesByCollection = new Map<string, Set<string>>();
  for (const plan of plans) {
    const set = namesByCollection.get(plan.collection) ?? new Set<string>();
    set.add(plan.options.name);
    namesByCollection.set(plan.collection, set);
  }

  for (const [collection, plannedNames] of namesByCollection) {
    if (!present.has(collection)) continue;
    if (!reconcilable(collection)) continue;
    const indexes = await db.collection(collection).indexes().catch(() => []) as ExistingIndex[];
    for (const index of indexes) {
      const verdict = classifyIndex(index, plannedNames, true);
      if (verdict === 'planned') continue;
      if (verdict !== 'obsolete') {
        console.log(`  keep:    ${collection}.${index.name} (not declared, ${verdict === 'engine' ? 'managed by the driver' : 'not provably safe to drop'})`);
        continue;
      }
      try {
        await db.collection(collection).dropIndex(index.name as string);
        console.log(`  dropped: ${collection}.${index.name} (no longer declared)`);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        console.log(`  keep:    ${collection}.${index.name} (could not be dropped: ${reason})`);
      }
    }
  }
}
