import { Db } from 'mongodb';
import { v5 as uuidv5 } from 'uuid';
import { RESOURCE_COLLECTION } from '../../../shared/models/collections';
import { newMeta, touchMeta, DEFAULT_TENANT_ID } from '../../../shared/models/base.model';
import { recordConfigurationChange } from '../../audit/services/configurationChange';
import { ResourceRecord, ResourceKind, ValidationMode } from '../models/resource.model';
import { PolicyRecord, selectorApplies } from '../models/policy.model';

/**
 * Reading the resource-server catalog back, and the one write it has.
 *
 * `registerCatalog` is the only write, whoever calls it: the application ships its enforcement
 * points in its own code and declares them here, because only the code containing a guard can say
 * a permission exists. Two callers reach it, an admin-token route for a resource server's own
 * deployment and an RBAC-gated route for a console operator with `permissions:manage`, and both go
 * through this one method so neither can drift from what the other accepts.
 */

// The same namespace the seeders use, so a catalog registered at boot and one registered from a
// console both resolve to one record rather than two that look alike.
const AUTHORIZATION_NAMESPACE = 'a1c4e7b2-5d9f-4a3c-8e6b-2f7d1c9a4b83';

export interface ResourceServerView {
  resourceId: string;
  name: string;
  displayName?: string;
  description?: string;
  kind: ResourceKind;
  audience?: string;
  catalogVersion: number;
  validationMode?: ValidationMode;
  status: ResourceRecord['status'];
  registeredAt?: string;
  resources: Array<{
    resourceId: string;
    name: string;
    displayName?: string;
    description?: string;
    actions: string[];
    status: ResourceRecord['status'];
    catalogVersion: number;
  }>;
}

export interface CatalogRegistration {
  resourceId: string;
  /** Permissions in the catalog after this call. */
  registered: number;
  /** Permissions no longer declared, kept for existing grants. */
  deprecated: number;
  catalogVersion: number;
}

export class ResourceAdminService {
  constructor(private readonly db: Db) {}

  private get resources() {
    return this.db.collection<ResourceRecord>(RESOURCE_COLLECTION);
  }

  /**
   * Every resource server this realm has registered, its own resources (the types it declares)
   * nested under it.
   *
   * Two reads, not one join per server: every top-level server first, then every child in one
   * `$in` query, grouped in memory by `parentResourceId`. A withdrawn server or resource is still
   * listed, status included, for the same reason `assignmentsFor` keeps a lapsed holding: "who used
   * to have this" is the question after something goes wrong.
   *
   * `q`/`status`/`skip`/`limit` narrow and page the top-level servers only: a server's own resource
   * types are few and stay nested under it whole, the same way a role's own permissions are never
   * paged independently of the role.
   */
  async list(
    realmId: string,
    options: { q?: string; status?: ResourceRecord['status']; skip?: number; limit?: number } = {},
  ): Promise<{ resourceServers: ResourceServerView[]; total: number }> {
    const skip = Math.max(0, options.skip ?? 0);
    const limit = Math.min(200, Math.max(1, options.limit ?? 20));
    const filter: Record<string, unknown> = { realmId, kind: { $ne: 'object' } };
    if (options.status) filter.status = options.status;
    if (options.q) {
      // Escaped, because a search box is not a place to accept an expression the database will
      // then run.
      const escaped = options.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { name: { $regex: escaped, $options: 'i' } },
        { audience: { $regex: escaped, $options: 'i' } },
      ];
    }

    const [servers, total] = await Promise.all([
      this.resources.find(filter, { projection: { _id: 0 } }).sort({ name: 1 }).skip(skip).limit(limit).toArray(),
      this.resources.countDocuments(filter),
    ]);
    if (servers.length === 0) return { resourceServers: [], total };

    const children = await this.resources
      .find(
        { realmId, parentResourceId: { $in: servers.map((server) => server.resourceId) } },
        { projection: { _id: 0 } },
      )
      .sort({ name: 1 })
      .toArray();

    const childrenByParent = new Map<string, ResourceRecord[]>();
    for (const child of children) {
      const list = childrenByParent.get(child.parentResourceId!) ?? [];
      list.push(child);
      childrenByParent.set(child.parentResourceId!, list);
    }

    return {
      total,
      resourceServers: servers.map((server) => ({
        resourceId: server.resourceId,
        name: server.name,
        ...(server.displayName ? { displayName: server.displayName } : {}),
        ...(server.description ? { description: server.description } : {}),
        kind: server.kind,
        ...(server.audience ? { audience: server.audience } : {}),
        catalogVersion: server.catalogVersion,
        ...(server.validationMode ? { validationMode: server.validationMode } : {}),
        status: server.status,
        ...(server.registeredAt ? { registeredAt: server.registeredAt } : {}),
        resources: (childrenByParent.get(server.resourceId) ?? []).map((child) => ({
          resourceId: child.resourceId,
          name: child.name,
          ...(child.displayName ? { displayName: child.displayName } : {}),
          ...(child.description ? { description: child.description } : {}),
          actions: child.actions,
          status: child.status,
          catalogVersion: child.catalogVersion,
        })),
      })),
    };
  }

  /**
   * Every resource in this realm that a policy's own `resource` selector actually matches.
   *
   * The same `selectorApplies` the decision engine and the resource-detail page's own
   * `?governs=` filter both use, run the other direction: given a policy, which of the realm's
   * own resources fall under it, `names` and `pattern` handled identically since matching a
   * catalog entry's name is the whole of what either one means. Only `kind: 'object'` entries
   * count, because those are the resource TYPES a decision is ever actually asked about; a
   * top-level server is never itself the target of one.
   */
  async matching(realmId: string, selector: PolicyRecord['resource']): Promise<Array<{
    resourceId: string; name: string; status: ResourceRecord['status'];
  }>> {
    const candidates = await this.resources
      .find({ realmId, kind: 'object' }, { projection: { _id: 0, resourceId: 1, name: 1, status: 1 } })
      .sort({ name: 1 })
      .toArray();
    return candidates
      .filter((candidate) => selectorApplies(selector, candidate.name))
      .map((candidate) => ({ resourceId: candidate.resourceId, name: candidate.name, status: candidate.status }));
  }

  /**
   * Declares (or replaces) one resource server's whole catalog.
   *
   * Idempotent by construction: `resourceId` and each child id are derived deterministically from
   * `realmId:name[:type]`, so registering the same catalog twice reaches the same records rather
   * than creating a second copy. The catalog is replaced as a BLOCK per resource type rather than
   * edited row by row (P5.2): a permission removed from the caller's own declaration but left in the
   * database would look exactly like one that still worked, and reviving it would need a
   * `deprecated` flag flipped back by hand. Anything no longer declared is marked withdrawn, never
   * deleted, because a role may still grant something over it and removing the resource would leave
   * that grant referring to nothing.
   *
   * Recorded as a configuration change (P/CI DSS 10.2.1.x: every administrative action). `actor` is
   * optional because one of the two callers is a resource server's own deployment script, not a
   * signed-in person, and "the deployment itself" is the honest actor for that call.
   */
  async registerCatalog(
    realmId: string,
    tenantId: string,
    name: string,
    input: {
      audience: string;
      catalogVersion?: number;
      validationMode?: ResourceRecord['validationMode'];
      permissions: Array<{ resource: string; action: string; description?: string }>;
    },
    actor = 'resource-server-deployment',
  ): Promise<CatalogRegistration> {
    const resourceId = uuidv5(`resource-server:${realmId}:${name}`, AUTHORIZATION_NAMESPACE);
    const servers = this.resources;

    const existing = await servers.findOne({ resourceId });
    // A NUMBER, because it is compared and incremented. As a string, '10' sorts below '9'.
    const version = Number(input.catalogVersion ?? 1);
    if (existing) {
      await servers.updateOne({ resourceId }, {
        $set: {
          name,
          audience: input.audience,
          catalogVersion: version,
          ...(input.validationMode ? { validationMode: input.validationMode } : {}),
          meta: touchMeta(existing.meta),
        },
      });
    } else {
      await servers.insertOne({
        realmId,
        tenantId: tenantId ?? DEFAULT_TENANT_ID,
        resourceId,
        name,
        audience: input.audience,
        // An API is one kind of resource among several. A tool and a Model Context Protocol server
        // are the others, and they go through the same decision function.
        kind: 'api',
        catalogVersion: version,
        actions: [],
        status: 'active',
        validationMode: input.validationMode ?? 'hybrid',
        registeredAt: new Date().toISOString(),
        meta: newMeta('Resource'),
      });
    }

    // Each resource TYPE the caller declares becomes a resource of its own, parented to the server.
    // That is what lets a permission stay the single string `type:action` while the server still
    // knows which types it enforces.
    const actionsByType = new Map<string, Set<string>>();
    for (const permission of input.permissions) {
      const held = actionsByType.get(permission.resource) ?? new Set<string>();
      held.add(permission.action);
      actionsByType.set(permission.resource, held);
    }

    let registered = 0;
    for (const [type, actions] of actionsByType) {
      const childId = uuidv5(`resource:${realmId}:${name}:${type}`, AUTHORIZATION_NAMESPACE);
      const declaredActions = [...actions].sort();
      const child = await servers.findOne({ resourceId: childId });
      if (child) {
        await servers.updateOne({ resourceId: childId }, {
          $set: {
            name: type,
            actions: declaredActions,
            // Bumped whenever the set changes, so drift is visible rather than silent.
            catalogVersion: JSON.stringify(child.actions ?? []) === JSON.stringify(declaredActions)
              ? child.catalogVersion
              : child.catalogVersion + 1,
            status: 'active',
            meta: touchMeta(child.meta),
          },
        });
      } else {
        await servers.insertOne({
          realmId,
          tenantId: tenantId ?? DEFAULT_TENANT_ID,
          resourceId: childId,
          name: type,
          // An object the server protects, reached through it rather than addressed by an audience
          // of its own.
          kind: 'object',
          parentResourceId: resourceId,
          actions: declaredActions,
          catalogVersion: 1,
          status: 'active',
          registeredAt: new Date().toISOString(),
          meta: newMeta('Resource'),
        });
      }
      registered += declaredActions.length;
    }

    // A type the caller no longer declares at all. Marked withdrawn, never deleted.
    const children = await servers
      .find({ realmId, parentResourceId: resourceId }, { projection: { _id: 0 } })
      .toArray();
    let withdrawn = 0;
    for (const child of children) {
      if (actionsByType.has(child.name)) continue;
      if (child.status === 'withdrawn') continue;
      await servers.updateOne({ resourceId: child.resourceId }, { $set: { status: 'withdrawn' } });
      withdrawn += 1;
    }

    // Diffed on the SERVER's own fields, not the children: "which attribute of this registration
    // moved" is answerable from those, and `registered`/`deprecated` above already say how much of
    // the declared catalog changed without a per-action diff nobody would read.
    await recordConfigurationChange(this.db, {
      realmId,
      tenantId,
      what: 'resource-server',
      ref: resourceId,
      operation: existing ? 'updated' : 'created',
      actorSubjectId: actor,
      before: existing ? { audience: existing.audience, catalogVersion: existing.catalogVersion, validationMode: existing.validationMode } : null,
      after: { audience: input.audience, catalogVersion: version, validationMode: input.validationMode ?? existing?.validationMode ?? 'hybrid' },
    });

    return { resourceId, registered, deprecated: withdrawn, catalogVersion: version };
  }
}
