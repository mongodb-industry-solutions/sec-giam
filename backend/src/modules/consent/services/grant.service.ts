import { Db } from 'mongodb';
import { GRANT_COLLECTION, CLIENT_COLLECTION } from '../../../shared/models/collections';
import { GrantRecord, grantedScopes } from '../models/grant.model';
import { ClientRecord } from '../../oauth/models/client.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { RealmRecord } from '../../realm/models/realm.model';

/**
 * What a principal has authorised a client to do, and the ability to take it back.
 *
 * Revocation is a state change, never a delete. A person asking "what did I once allow, and when did
 * I stop allowing it" is asking a question a deleted row cannot answer, and it is exactly the
 * question that matters after something has gone wrong.
 */

export interface GrantView {
  grantId: string;
  clientId: string;
  clientName: string;
  logoUri?: string;
  scopes: string[];
  status: 'active' | 'revoked';
  grantedAt: string;
  revokedAt?: string;
  lastUsedAt?: string;
}

export type GrantStatusFilter = 'active' | 'revoked' | 'all';

export class GrantService {
  constructor(private readonly db: Db) {}

  private get grants() {
    return this.db.collection<GrantRecord>(GRANT_COLLECTION);
  }

  /** The client's display name and logo travel with the grant, so a caller needs no second read. */
  private async decorate(realmId: string, records: GrantRecord[]): Promise<GrantView[]> {
    const clientIds = [...new Set(records.map((grant) => grant.clientId))];
    const clients = await this.db.collection<ClientRecord>(CLIENT_COLLECTION)
      .find({ realmId, clientId: { $in: clientIds } }, { projection: { _id: 0, clientId: 1, clientName: 1, logoUri: 1 } })
      .toArray() as unknown as Array<Pick<ClientRecord, 'clientId' | 'clientName' | 'logoUri'>>;
    const byId = new Map(clients.map((client) => [client.clientId, client]));

    return records.map((grant) => {
      const client = byId.get(grant.clientId);
      return {
        grantId: grant.grantId,
        clientId: grant.clientId,
        clientName: client?.clientName ?? grant.clientId,
        ...(client?.logoUri ? { logoUri: client.logoUri } : {}),
        scopes: grantedScopes(grant),
        status: grant.status,
        grantedAt: grant.grantedAt,
        ...(grant.revokedAt ? { revokedAt: grant.revokedAt } : {}),
        ...(grant.lastUsedAt ? { lastUsedAt: grant.lastUsedAt } : {}),
      };
    });
  }

  async list(realmId: string, subjectId: string, status: GrantStatusFilter = 'all'): Promise<GrantView[]> {
    const records = await this.grants
      .find(
        { realmId, subjectId, ...(status === 'all' ? {} : { status }) },
        { projection: { _id: 0 } },
      )
      .sort({ grantedAt: -1 })
      .toArray();
    return this.decorate(realmId, records);
  }

  /** Everyone who has authorised one client. An oversight view, gated by the caller. */
  async listForClient(realmId: string, clientId: string, status: GrantStatusFilter = 'all'): Promise<GrantView[]> {
    const records = await this.grants
      .find({ realmId, clientId, ...(status === 'all' ? {} : { status }) }, { projection: { _id: 0 } })
      .sort({ grantedAt: -1 })
      .toArray();
    return this.decorate(realmId, records);
  }

  async byId(realmId: string, subjectId: string, grantId: string): Promise<GrantView | null> {
    // Owner scoped in the query itself, so another principal's grant is simply not found rather than
    // found and then refused. The two are indistinguishable to the caller, which is the point.
    const record = await this.grants.findOne({ realmId, subjectId, grantId }, { projection: { _id: 0 } });
    if (!record) return null;
    return (await this.decorate(realmId, [record]))[0];
  }

  async revoke(realm: RealmRecord, subjectId: string, grantId: string): Promise<boolean> {
    const result = await this.grants.updateOne(
      { realmId: realm.realmId, subjectId, grantId, status: 'active' },
      { $set: { status: 'revoked', revokedAt: new Date().toISOString(), 'meta.lastModified': new Date().toISOString() } },
    );
    if (result.matchedCount === 0) return false;

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'consent',
      action: 'grant.revoked',
      outcome: 'success',
      subjectId,
      target: { type: 'grant', ref: grantId },
    });
    return true;
  }

  async reactivate(realm: RealmRecord, subjectId: string, grantId: string): Promise<boolean> {
    const result = await this.grants.updateOne(
      { realmId: realm.realmId, subjectId, grantId, status: 'revoked' },
      { $set: { status: 'active', 'meta.lastModified': new Date().toISOString() }, $unset: { revokedAt: '' } },
    );
    if (result.matchedCount === 0) return false;

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'consent',
      action: 'grant.reactivated',
      outcome: 'success',
      subjectId,
      target: { type: 'grant', ref: grantId },
    });
    return true;
  }
}
