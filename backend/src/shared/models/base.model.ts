// The shape every GIAM record shares. Security-standard vocabulary only: no industry naming, no
// service-domain field, no *InstanceReference suffix and no party* prefix.

// SCIM 2.0 core schema, common attributes. Replaces the platform's created/updated/schemaVersion trio.
export interface Meta {
  created: string;
  lastModified: string;
  // Monotonic per record. Also what an ETag is derived from on a mutable resource.
  version: number;
  resourceType?: string;
}

export function newMeta(resourceType?: string, at: Date = new Date()): Meta {
  const stamp = at.toISOString();
  return { created: stamp, lastModified: stamp, version: 1, ...(resourceType && { resourceType }) };
}

export function touchMeta(meta: Meta, at: Date = new Date()): Meta {
  return { ...meta, lastModified: at.toISOString(), version: meta.version + 1 };
}

/**
 * The partition every record carries from its first version.
 *
 * A realm is a trust and key boundary: separate signing keys, separate issuer, and a token minted in
 * one is refused by the other. A tenant is a data boundary inside it, because one realm may serve many
 * customers. Conflating the two is the mistake that makes multi-tenancy unretrofittable, and adding
 * either later means touching every query and changing a shard key that cannot be changed.
 */
export interface Scoped {
  realmId: string;
  tenantId: string;
}

// The tenant every realm gets so the field is never empty and no query needs a null branch.
export const DEFAULT_TENANT_ID = 'default';

/** An opaque back-reference to a record in a consuming application. GIAM never resolves it. */
export interface OwnerRef {
  // Free-form on purpose: a consumer's record kind is the consumer's business, not GIAM's.
  kind: string;
  ref: string;
  // Denormalized at registration, so GIAM can render an owner without calling anyone.
  displayName?: string;
}

/** A reference to something a relationship or an audit record points at. */
export interface TargetRef {
  type: string;
  ref: string;
}
