import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A tenant: a data boundary inside a realm.
 *
 * A realm is a trust and key boundary, a tenant is a data one, and one realm may serve many tenants.
 * Every other record carries `tenantId` and every query is tenant-scoped by default, from the first
 * version, even while there is one tenant per realm. Adding the field later would mean touching every
 * query and changing a shard key that cannot be changed.
 *
 * Tenants nest, because an organisation that has customers usually has departments too.
 */
export interface TenantRecord extends Scoped {
  name: string;
  displayName: string;
  parentTenantId?: string;
  status: 'active' | 'suspended';
  meta: Meta;
}
