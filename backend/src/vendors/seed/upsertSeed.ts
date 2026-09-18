import { Collection, Db, Document, Filter, OptionalUnlessRequiredId } from 'mongodb';
import { Meta, newMeta, touchMeta } from '../../shared/models/base.model';
import { collectionsWithRetiredFields } from '../../shared/models/collections';
import { PrincipalRecord, RoleHolding } from '../../modules/directory/models/principal.model';
import { CredentialRecord } from '../../modules/directory/models/credential.model';

/**
 * The moment a seeded grant records as having been made.
 *
 * Fixed rather than `now`, because a reseed that changes nothing must WRITE nothing, and a wall
 * clock guarantees the opposite: every run would differ in this field alone and every holding would
 * report as updated. Seeded data has no real grant time, so inventing a stable one is honest.
 */
export const SEED_GRANTED_AT = '2026-01-01T00:00:00.000Z';

// The one way a seeder writes a record: idempotent, and only in the fields the fixture owns.
// It reads first because `meta` cannot be initialised and touched in one update, and because
// `meta.version` backs an ETag: a reseed that changes nothing must write nothing.
export interface SeedOutcome {
  action: 'created' | 'updated' | 'unchanged';
}

export async function upsertSeed<T extends Document & { meta: Meta }>(
  collection: Collection<T>,
  filter: Filter<T>,
  owned: Partial<T>,
  onInsert: Partial<T>,
  resourceType?: string,
): Promise<SeedOutcome> {
  const existing = await collection.findOne(filter);

  if (!existing) {
    await collection.insertOne({
      ...onInsert,
      ...owned,
      meta: newMeta(resourceType),
    } as OptionalUnlessRequiredId<T>);
    return { action: 'created' };
  }

  const changed = Object.entries(owned).filter(([key, value]) => {
    const current = (existing as Document)[key];
    return JSON.stringify(current) !== JSON.stringify(value);
  });
  if (changed.length === 0) return { action: 'unchanged' };

  await collection.updateOne(filter, {
    $set: { ...Object.fromEntries(changed), meta: touchMeta(existing.meta) },
  } as never);
  return { action: 'updated' };
}

/**
 * The one way a seeder writes a role holding, now that a holding lives inside its principal.
 *
 * Idempotent in the same sense `upsertSeed` is, and identified the same way the rest of the system
 * identifies a holding: by `roleId`, plus the scope reference when it has one, so a principal can
 * hold the same role at home and pointed at another realm without the two colliding.
 *
 * A missing principal throws rather than passing silently. An unmatched update would otherwise
 * report success while granting nothing, which is the failure that leaves an interface showing a
 * role that every check denies.
 */
/**
 * The one way a seeder writes a role holding, to whichever document declares `roles`.
 *
 * ADR-004 gave `CredentialRecord` the same `roles?: RoleHolding[]` shape a principal's had, resolved
 * through the same decision-point pipeline; this is the seed-side half of that, so a credential's OWN
 * grant is as reproducible on a reset as a principal's always was, rather than only reachable by
 * hand.
 */
async function upsertRoleHolding<T extends Document & { roles?: RoleHolding[] }>(
  collection: Collection<T>,
  key: Filter<T>,
  holding: RoleHolding,
  notFoundLabel: string,
): Promise<SeedOutcome> {
  const identity: Document = holding.scope
    ? { roleId: holding.roleId, 'scope.ref': holding.scope.ref }
    : { roleId: holding.roleId, scope: { $exists: false } };

  const existing = await collection.findOne(
    { ...key, roles: { $elemMatch: identity } } as Filter<T>,
    { projection: { _id: 0, roles: 1 } },
  );

  if (existing) {
    const current = ((existing as { roles?: RoleHolding[] }).roles ?? []).find((entry) => (holding.scope
      ? entry.roleId === holding.roleId && entry.scope?.ref === holding.scope.ref
      : entry.roleId === holding.roleId && !entry.scope));
    if (current && JSON.stringify(current) === JSON.stringify(holding)) return { action: 'unchanged' };
    await collection.updateOne(
      { ...key, roles: { $elemMatch: identity } } as Filter<T>,
      { $set: { 'roles.$': holding } } as never,
    );
    return { action: 'updated' };
  }

  const appended = await collection.updateOne(
    { ...key, roles: { $not: { $elemMatch: identity } } } as Filter<T>,
    { $push: { roles: holding } } as never,
  );
  if (appended.matchedCount === 0) {
    throw new Error(`no ${notFoundLabel} to hold role ${holding.roleId}`);
  }
  return { action: 'created' };
}

/**
 * The one way a seeder writes a role holding, now that a holding lives inside its principal.
 *
 * Idempotent in the same sense `upsertSeed` is, and identified the same way the rest of the system
 * identifies a holding: by `roleId`, plus the scope reference when it has one, so a principal can
 * hold the same role at home and pointed at another realm without the two colliding.
 *
 * A missing principal throws rather than passing silently. An unmatched update would otherwise
 * report success while granting nothing, which is the failure that leaves an interface showing a
 * role that every check denies.
 */
export async function upsertHolding(
  principals: Collection<PrincipalRecord>,
  key: { realmId: string; subjectId: string },
  holding: RoleHolding,
): Promise<SeedOutcome> {
  return upsertRoleHolding(principals, key, holding, `principal ${key.subjectId} in realm ${key.realmId}`);
}

/**
 * The same thing, for a CREDENTIAL's own holding (ADR-004).
 *
 * A missing credential throws for the same reason a missing principal does: an unmatched update
 * would report success while the credential remains scoped exactly as before, and the operator would
 * have no way to tell the seed step from a real refusal.
 */
export async function upsertCredentialHolding(
  credentials: Collection<CredentialRecord>,
  key: { realmId: string; credentialId: string },
  holding: RoleHolding,
): Promise<SeedOutcome> {
  return upsertRoleHolding(credentials, key, holding, `credential ${key.credentialId} in realm ${key.realmId}`);
}

// Unsets only the fields a model DECLARES retired: no document is deleted, no other field is touched.
export async function retireDeclaredFields(db: Db): Promise<void> {
  const existing = new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));

  for (const spec of collectionsWithRetiredFields()) {
    if (!existing.has(spec.name)) continue;
    const fields = spec.retiredFields ?? [];
    const filter = { $or: fields.map((field) => ({ [field]: { $exists: true } })) };
    const affected = await db.collection(spec.name).countDocuments(filter);
    if (affected === 0) continue;
    await db.collection(spec.name).updateMany(filter, {
      $unset: Object.fromEntries(fields.map((field) => [field, ''])),
    });
    console.log(`  retired: ${spec.name}.${fields.join(', ')} removed from ${affected} document(s)`);
  }
}
