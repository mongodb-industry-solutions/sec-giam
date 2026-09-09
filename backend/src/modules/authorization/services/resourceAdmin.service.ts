import { Db } from 'mongodb';
import { RESOURCE_COLLECTION } from '../../../shared/models/collections';
import { ResourceRecord, ResourceKind, ValidationMode } from '../models/resource.model';

/**
 * Reading the resource-server catalog back, for a console to show what
 * `PUT /admin/resource-servers/:name/permissions` has registered.
 *
 * That endpoint is the only WRITE this catalog has, and it stays that way: "the application ships
 * its enforcement points in its own code and PUTs them here, because only the code containing a
 * guard can say the permission exists" (resource.controller.ts). This service only ever reads.
 */

export interface ResourceServerView {
  resourceId: string;
  name: string;
  kind: ResourceKind;
  audience?: string;
  catalogVersion: number;
  validationMode?: ValidationMode;
  status: ResourceRecord['status'];
  registeredAt?: string;
  resources: Array<{
    resourceId: string;
    name: string;
    actions: string[];
    status: ResourceRecord['status'];
    catalogVersion: number;
  }>;
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
   */
  async list(realmId: string): Promise<ResourceServerView[]> {
    const servers = await this.resources
      .find({ realmId, kind: { $ne: 'object' } }, { projection: { _id: 0 } })
      .sort({ name: 1 })
      .toArray();
    if (servers.length === 0) return [];

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

    return servers.map((server) => ({
      resourceId: server.resourceId,
      name: server.name,
      kind: server.kind,
      ...(server.audience ? { audience: server.audience } : {}),
      catalogVersion: server.catalogVersion,
      ...(server.validationMode ? { validationMode: server.validationMode } : {}),
      status: server.status,
      ...(server.registeredAt ? { registeredAt: server.registeredAt } : {}),
      resources: (childrenByParent.get(server.resourceId) ?? []).map((child) => ({
        resourceId: child.resourceId,
        name: child.name,
        actions: child.actions,
        status: child.status,
        catalogVersion: child.catalogVersion,
      })),
    }));
  }
}
