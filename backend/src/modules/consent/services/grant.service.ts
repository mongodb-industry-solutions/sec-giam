import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { GRANT_COLLECTION } from '../../../shared/models/collections';
import { listOAuthClients } from '../../oauth/services/clientAuth.service';
import { GrantRecord, grantedScopes, covers } from '../models/grant.model';
import { OAuthClient } from '../../oauth/models/client.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { RealmRecord } from '../../realm/models/realm.model';
import { newMeta } from '../../../shared/models/base.model';

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

  /**
   * Whether this person has already authorised this client for everything it is now asking.
   *
   * A partial grant is not a grant: a client that widens its scope is asking a new question, and the
   * person gets to answer it. A revoked grant never satisfies this, so withdrawing access means the
   * next authorization asks again rather than silently succeeding.
   */
  async covers(realmId: string, subjectId: string, clientId: string, requested: string[]): Promise<boolean> {
    const grant = await this.grants.findOne(
      { realmId, subjectId, clientId },
      { projection: { _id: 0, scope: 1, status: 1 } },
    );
    return Boolean(grant && covers(grant, requested));
  }

  /** The client's display name and logo travel with the grant, so a caller needs no second read. */
  private async decorate(realmId: string, records: GrantRecord[]): Promise<GrantView[]> {
    const clientIds = [...new Set(records.map((grant) => grant.clientId))];
    const clients = (await listOAuthClients(this.db, realmId))
      .filter((client) => clientIds.includes(client.clientId));
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

  /**
   * Records the authorisation a completed flow establishes.
   *
   * Emitted when the grant is first created and again when its scopes widen, because "this
   * application may now also move your money" is a new fact. A repeat of the same scopes is not an
   * event: it is the same authorisation being exercised, and recording it every time would bury the
   * moment consent actually changed.
   *
   * A withdrawn grant is left withdrawn. Restoring one gives access back without the person
   * approving anything, so it stays their own explicit act and never a side effect of a sign-in.
   */
  async consent(
    realm: RealmRecord,
    subjectId: string,
    client: Pick<OAuthClient, 'clientId' | 'clientName'>,
    scopes: string[],
  ): Promise<void> {
    if (scopes.length === 0) return;
    const now = new Date().toISOString();
    const existing = await this.grants.findOne(
      { realmId: realm.realmId, subjectId, clientId: client.clientId },
      { projection: { _id: 0 } },
    );
    if (existing?.status === 'revoked') return;

    const held = existing ? grantedScopes(existing) : [];
    const merged = [...new Set([...held, ...scopes])];
    const grantId = existing?.grantId ?? uuidv4();

    if (existing) {
      await this.grants.updateOne(
        { grantId: existing.grantId },
        { $set: { scope: merged.join(' '), lastUsedAt: now, 'meta.lastModified': now } },
      );
      if (merged.length === held.length) return;
    } else {
      await this.grants.insertOne({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        grantId,
        subjectId,
        clientId: client.clientId,
        scope: merged.join(' '),
        status: 'active',
        grantedAt: now,
        lastUsedAt: now,
        meta: newMeta('Grant'),
      } as GrantRecord);
    }

    // No stakeholder list: creating a grant is always the person's own approval, recorded against
    // them, so they already read it through their own subject.
    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'consent',
      action: 'grant.created',
      outcome: 'success',
      subjectId,
      clientId: client.clientId,
      target: { type: 'grant', ref: grantId },
      detail: { clientName: client.clientName, scope: merged, added: merged.filter((scope) => !held.includes(scope)) },
    });
  }

  /**
   * Who the event is recorded against, and who else may read it.
   *
   * Withdrawal is the one consent operation somebody other than the owner may perform. When they do,
   * the act belongs in the ACTOR's trail, and the owner is named as a stakeholder so it also reaches
   * the person whose authorisation it was. When the owner did it themselves, which is the ordinary
   * case, this collapses to exactly what it was before.
   */
  private attribution(subjectId: string, actorSubjectId?: string) {
    if (!actorSubjectId || actorSubjectId === subjectId) return { subjectId };
    return { subjectId: actorSubjectId, principalSubjectId: subjectId, stakeholderSubjectIds: [subjectId] };
  }

  async revoke(realm: RealmRecord, subjectId: string, grantId: string, actorSubjectId?: string): Promise<boolean> {
    const now = new Date().toISOString();
    // Returned rather than counted, so the event can name the application the person withdrew from.
    const record = await this.grants.findOneAndUpdate(
      { realmId: realm.realmId, subjectId, grantId, status: 'active' },
      { $set: { status: 'revoked', revokedAt: now, 'meta.lastModified': now } },
    );
    if (!record) return false;

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'consent',
      action: 'grant.revoked',
      outcome: 'success',
      ...this.attribution(subjectId, actorSubjectId),
      clientId: record.clientId,
      target: { type: 'grant', ref: grantId },
      detail: { scope: grantedScopes(record) },
    });
    return true;
  }

  async reactivate(realm: RealmRecord, subjectId: string, grantId: string, actorSubjectId?: string): Promise<boolean> {
    const record = await this.grants.findOneAndUpdate(
      { realmId: realm.realmId, subjectId, grantId, status: 'revoked' },
      { $set: { status: 'active', 'meta.lastModified': new Date().toISOString() }, $unset: { revokedAt: '' } },
    );
    if (!record) return false;

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'consent',
      action: 'grant.reactivated',
      outcome: 'success',
      ...this.attribution(subjectId, actorSubjectId),
      clientId: record.clientId,
      target: { type: 'grant', ref: grantId },
      detail: { scope: grantedScopes(record) },
    });
    return true;
  }
}
