import { Db, IndexSpecification, CreateIndexesOptions } from 'mongodb';
import {
  GIAM_COLLECTIONS, collectionSpec,
  REALM_COLLECTION, DOMAIN_COLLECTION,
  PRINCIPAL_COLLECTION, CREDENTIAL_COLLECTION,
  TICKET_COLLECTION,
  KEY_COLLECTION, RESOURCE_COLLECTION, ROLE_COLLECTION,
  POLICY_COLLECTION,
  SESSION_COLLECTION, GRANT_COLLECTION,
  AUDIT_COLLECTION,
  CASE_INSENSITIVE,
} from '../../shared/models/collections';

export interface IndexPlan {
  collection: string;
  keys: IndexSpecification;
  options: CreateIndexesOptions & { name: string };
}

/**
 * Every index GIAM declares, in one list so setup creates it and validation checks the same thing.
 *
 * Two rules shape the list, and the second one is stated CORRECTLY here for the first time.
 *
 * Uniqueness is per REALM wherever a value is only unique inside one, because two realms are two
 * institutions and a user name that collides across them is not a collision. The exceptions are
 * deliberate and few: an identifier resolved WITHOUT a realm in hand, such as a key id or a
 * subject id, is globally unique, because the question a verifier asks is which realm the thing
 * belongs to.
 *
 * Every compound index on a scoped collection leads with `realmId`.
 *
 * The header used to claim the pair `{realmId, tenantId}` led every one of them, and it did not:
 * three of thirty-four do. Rather than widen thirty-one indexes for a field that is invariably
 * `default`, the CLAIM is corrected, which the ADR open item explicitly allows. The property that
 * matters is preserved either way: `{realmId, tenantId}` is the shard key, `realmId` is a prefix
 * of it, and a query narrowing by `realmId` alone is therefore still targetable on a sharded
 * deployment. Adding `tenantId` to every index would cost storage and write amplification on every
 * one of them to express something the prefix already gives.
 *
 * The day-one invariant test asserts exactly this, so the claim cannot drift from the list again.
 */
export function plannedIndexes(): IndexPlan[] {
  const plans: IndexPlan[] = [
    // Realm and federation.
    { collection: REALM_COLLECTION, keys: { realmId: 1 }, options: { name: 'realmId_unique', unique: true } },
    /**
     * Case-insensitive, and the UNIQUENESS is the important half.
     *
     * Without the collation a deployment could hold `Acme` and `acme` as two realms, and a request
     * naming either would then have two right answers. With it the second one is refused at
     * creation, which is what makes resolving a name without case a safe thing to do at all.
     */
    {
      collection: REALM_COLLECTION,
      keys: { name: 1 },
      options: { name: 'name_unique', unique: true, collation: CASE_INSENSITIVE },
    },
    // Resolving an issuer URL back to its realm happens on every token verification path.
    { collection: REALM_COLLECTION, keys: { issuer: 1 }, options: { name: 'issuer_unique', unique: true } },
    // The wire alias a caller may use instead of the realm's own name.
    // Same collation as `name_unique`: `byName` looks in both with one query, and an index without
    // it would serve half of that query and scan for the other half.
    {
      collection: REALM_COLLECTION,
      keys: { aliases: 1 },
      options: { name: 'aliases', sparse: true, collation: CASE_INSENSITIVE },
    },

    { collection: DOMAIN_COLLECTION, keys: { domainId: 1 }, options: { name: 'domainId_unique', unique: true } },
    // A domain slug is unique inside its realm without case, for the same reason a realm's is:
    // `atlas-id` and `Atlas-Id` naming two paths into one realm is not a distinction anybody meant.
    {
      collection: DOMAIN_COLLECTION,
      keys: { realmId: 1, tenantId: 1, name: 1 },
      options: { name: 'realm_tenant_name_unique', unique: true, collation: CASE_INSENSITIVE },
    },
    // Home-realm discovery resolves an entered email domain to a provider.
    { collection: DOMAIN_COLLECTION, keys: { realmId: 1, 'config.emailDomains': 1 }, options: { name: 'realm_emailDomains', sparse: true } },

    // Directory.
    { collection: PRINCIPAL_COLLECTION, keys: { subjectId: 1 }, options: { name: 'subjectId_unique', unique: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, userName: 1 }, options: { name: 'realm_userName_unique', unique: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, tenantId: 1, kind: 1, lifecycleState: 1 }, options: { name: 'realm_tenant_kind_state' } },
    // SCIM correlation for inbound provisioning. Sparse: only a federated or provisioned record has one.
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, externalId: 1 }, options: { name: 'realm_externalId', sparse: true } },
    { collection: PRINCIPAL_COLLECTION, keys: { realmId: 1, domainId: 1 }, options: { name: 'realm_domainId', sparse: true } },
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
    { collection: CREDENTIAL_COLLECTION, keys: { ownerId: 1 }, options: { name: 'ownerId', sparse: true } },
    // RFC 8705: locating the credential bound to a presented certificate.
    { collection: CREDENTIAL_COLLECTION, keys: { 'metadata.mtls.certificateThumbprint': 1 }, options: { name: 'mtls_thumbprint', sparse: true } },

    // OAuth.
    { collection: TICKET_COLLECTION, keys: { requestId: 1 }, options: { name: 'requestId_unique', unique: true } },
    // The code is stored hashed, and looked up by that hash on redemption.
    { collection: TICKET_COLLECTION, keys: { realmId: 1, codeHash: 1 }, options: { name: 'realm_codeHash', sparse: true } },
    { collection: TICKET_COLLECTION, keys: { authReqId: 1 }, options: { name: 'authReqId', sparse: true } },
    { collection: TICKET_COLLECTION, keys: { realmId: 1, subjectId: 1, status: 1 }, options: { name: 'realm_subject_status', sparse: true } },
    // Expiry is the database's job: a cleanup job is a thing that fails silently.
    { collection: TICKET_COLLECTION, keys: { expiresAt: 1 }, options: { name: 'expiresAt_ttl', expireAfterSeconds: 0 } },

    // No index for a revoked-token list, and no TTL with a grace beyond expiry to keep one
    // detectable. Both existed to serve the token collection, and nothing redeemable is stored now:
    // a replay is detected by the refresh generation on the session, not by a retained copy.

    { collection: KEY_COLLECTION, keys: { kid: 1 }, options: { name: 'kid_unique', unique: true } },
    // The JWKS read: every key a realm still publishes, on every verification cold start.
    { collection: KEY_COLLECTION, keys: { realmId: 1, status: 1, notAfter: 1 }, options: { name: 'realm_status_notAfter' } },
    // Lease renewal, and finding the keys whose owning replica has gone away.
    { collection: KEY_COLLECTION, keys: { realmId: 1, instanceId: 1 }, options: { name: 'realm_instanceId', sparse: true } },
    { collection: KEY_COLLECTION, keys: { leaseExpiresAt: 1 }, options: { name: 'leaseExpiresAt', sparse: true } },

    // Authorization.
    // One collection for an API, a tool and a Model Context Protocol server: they are the same kind
    // of thing, something a decision is made ABOUT.
    { collection: RESOURCE_COLLECTION, keys: { realmId: 1, resourceId: 1 }, options: { name: 'realm_resourceId_unique', unique: true } },
    { collection: RESOURCE_COLLECTION, keys: { realmId: 1, kind: 1 }, options: { name: 'realm_kind' } },
    // What a token names in `aud`. Sparse: only an api carries one, a tool is reached through its server.
    { collection: RESOURCE_COLLECTION, keys: { realmId: 1, audience: 1 }, options: { name: 'realm_audience', sparse: true } },
    // A resource may contain resources, so a server exposing tools needs no collection of its own.
    { collection: RESOURCE_COLLECTION, keys: { realmId: 1, parentResourceId: 1 }, options: { name: 'realm_parentResourceId', sparse: true } },


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
    // Exactly the fields the evaluator's own query filters by, in the order it filters them, so a
    // decision does not read every active policy in the realm to decide about one resource. `enabled`
    // was the pre-v40 field; `status` replaced it and this index had not caught up.
    { collection: POLICY_COLLECTION, keys: { realmId: 1, tenantId: 1, status: 1 }, options: { name: 'realm_tenant_status' } },
    // The fast path: a resource named exactly, a plain multikey equality lookup.
    { collection: POLICY_COLLECTION, keys: { realmId: 1, 'resource.ids': 1 }, options: { name: 'realm_resource_ids' } },
    // Existence only, sparse: a `pattern` policy cannot be excluded by an index (it is a regular
    // expression, not a value to compare against), so this only needs to answer "does this policy use
    // the slower form at all", cheaply, without touching the far more common `ids` policies.
    {
      collection: POLICY_COLLECTION,
      keys: { realmId: 1, 'resource.pattern': 1 },
      options: { name: 'realm_resource_pattern', sparse: true },
    },
    // The role-triggered resync (`PolicyAdminService.resyncRoleReferences`) finds every policy
    // naming a changed role by this field; a `role.pattern` policy is caught the sparse way, same
    // reasoning as `resource.pattern` just above.
    { collection: POLICY_COLLECTION, keys: { realmId: 1, 'role.ids': 1 }, options: { name: 'realm_role_ids', sparse: true } },
    {
      collection: POLICY_COLLECTION,
      keys: { realmId: 1, 'role.pattern': 1 },
      options: { name: 'realm_role_pattern', sparse: true },
    },

    // Sessions and consent.
    { collection: SESSION_COLLECTION, keys: { sessionId: 1 }, options: { name: 'sessionId_unique', unique: true } },
    /**
     * Revocation, all four shapes, and every one of them is a delete against one of these.
     *
     * `{realmId, subjectId}` is a leaver or a compromised account. `{realmId, clientId}` is a
     * retired application. `{realmId}` alone is single logout across a realm. The subject index
     * also serves the concurrent-session limit, which counts per subject within the realm.
     */
    { collection: SESSION_COLLECTION, keys: { realmId: 1, clientId: 1 }, options: { name: 'realm_clientId', sparse: true } },
    { collection: SESSION_COLLECTION, keys: { realmId: 1, domainId: 1 }, options: { name: 'realm_domainId', sparse: true } },
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
    /**
     * "Every event in this flow", which is the first query a post-incident investigation runs.
     *
     * `correlationId` stays a MEASUREMENT field and is deliberately NOT moved into `meta`, though
     * that is where a time series collection filters most cheaply. The `metaField` determines
     * bucketing, and this field holds one distinct value per flow, which is near-maximal
     * cardinality: each bucket would end up holding almost a single measurement, destroying the
     * columnar compression that is the reason to use a time series collection at all.
     *
     * A secondary index on a measurement field is supported from MongoDB 6.0 and this deployment
     * runs 8.x, so the query is served without touching how the data is laid out.
     */
    {
      collection: AUDIT_COLLECTION,
      keys: { realmId: 1, correlationId: 1, ts: -1 },
      options: { name: 'realm_correlation_ts' },
    },
  ];

  /**
   * Only plans for collections the registry names.
   *
   * The registry decides what exists; this list decides how it is indexed. When a collection leaves
   * the registry, setup stops creating it and `--reset` drops it, so a surviving plan asks for an
   * index on a collection that is not there. That reports as a validation failure naming an index
   * nobody declared on purpose, which is a confusing way to learn that a plan was left behind.
   *
   * Filtered rather than asserted, because during a consolidation a collection leaves the registry
   * one phase before the code that wrote to it goes, and a hard failure there would block the very
   * refactor that removes it.
   */
  const registered = new Set(GIAM_COLLECTIONS.map((spec) => spec.name));
  return plans.filter((plan) => registered.has(plan.collection));
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
      /**
       * The same NAME with different OPTIONS is a redeclaration, and it is rebuilt.
       *
       * MongoDB refuses it rather than adapting, which is right of the server and wrong for setup:
       * changing an index's options in the plan is an ordinary thing to do (this is how
       * `name_unique` gained its collation), and a deployment holding the old one would otherwise
       * be stuck until somebody dropped it by hand. Dropping and recreating is what an operator
       * would do, so setup does it and says so.
       *
       * Both refusals, because the server distinguishes them and the distinction does not matter
       * here: `IndexOptionsConflict` (85) is the same key with different options, and
       * `IndexKeySpecsConflict` (86) is the same NAME with a different specification, which is
       * what adding a collation produces.
       *
       * Only for a conflict on an index THIS plan declares, and only by its declared name. Any
       * other failure still throws: a disagreement setup cannot name is one it must not paper over.
       */
      const code = (err as { code?: number }).code;
      const conflict = code === 85 || code === 86;
      if (conflict) {
        console.log(`  rebuild: ${plan.collection}.${plan.options.name} (declared options changed)`);
        await db.collection(plan.collection).dropIndex(plan.options.name);
        await db.collection(plan.collection).createIndex(plan.keys, plan.options);
        console.log(`  index:   ${plan.collection}.${plan.options.name}`);
        continue;
      }
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
