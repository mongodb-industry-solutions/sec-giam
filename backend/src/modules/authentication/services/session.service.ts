import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { newMeta } from '../../../shared/models/base.model';
import { SESSION_COLLECTION } from '../../../shared/models/collections';
import { SessionRecord, isLive } from '../models/session.model';
import { DirectoryService } from '../../directory/services/directory.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { ClientRecord } from '../../oauth/models/client.model';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';

/**
 * Sessions, and ending them.
 *
 * The session used to be an implication: a signed cookie and a counter. Nothing could list one, end
 * one from elsewhere, or count how many a principal had. Making it a record is what turns single
 * logout and "sign this person out everywhere" from claims into operations.
 *
 * Ending a session does three things, and all three are needed. It terminates the record, so nothing
 * can be authorised from it again. It revokes the tokens issued under it, so anything outstanding
 * stops working rather than running to expiry. And it raises the principal's epoch, which retires
 * every token issued before now WITHOUT listing them, including any this authority never recorded.
 */
export class SessionService {
  constructor(private readonly db: Db) {}

  private get sessions() {
    return this.db.collection<SessionRecord>(SESSION_COLLECTION);
  }

  /**
   * Opens a session for a principal that has just authenticated.
   *
   * Here rather than in each controller because a password sign-in and a federated one must produce
   * the SAME session: the same lifetimes, the same epoch, the same shape. Two places building this
   * record is how one of them quietly ends up without an idle timeout.
   */
  async start(input: {
    realm: { realmId: string; tenantId: string; tokenPolicy: { sessionMaxTtlSeconds: number; sessionIdleTtlSeconds: number } };
    subjectId: string;
    epoch?: number;
    userAgentHash?: string;
    ipHash?: string;
  }): Promise<SessionRecord> {
    const now = new Date();
    const session: SessionRecord = {
      realmId: input.realm.realmId,
      tenantId: input.realm.tenantId,
      sessionId: uuidv4(),
      subjectId: input.subjectId,
      epoch: input.epoch ?? 0,
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + input.realm.tokenPolicy.sessionMaxTtlSeconds * 1000).toISOString(),
      idleExpiresAt: new Date(now.getTime() + input.realm.tokenPolicy.sessionIdleTtlSeconds * 1000).toISOString(),
      clientIds: [],
      ...(input.userAgentHash ? { userAgentHash: input.userAgentHash } : {}),
      ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      meta: newMeta('Session'),
    };
    await this.sessions.insertOne(session);
    return session;
  }

  async find(realmId: string, sessionId: string): Promise<SessionRecord | null> {
    return this.sessions.findOne({ realmId, sessionId }, { projection: { _id: 0 } });
  }

  /** Live sessions for a principal, so a console can show them and an operator can end one. */
  async listFor(realmId: string, subjectId: string): Promise<SessionRecord[]> {
    const held = await this.sessions
      .find({ realmId, subjectId, terminatedAt: { $exists: false } }, { projection: { _id: 0 } })
      .sort({ lastSeenAt: -1 })
      .toArray();
    // Expiry is judged here rather than left to the sweep: a session that lapsed a second ago is not
    // live, whatever the database has got round to removing.
    return held.filter((session) => isLive(session));
  }

  /** Moves the idle window forward. An absolute expiry is never extended. */
  async touch(realmId: string, sessionId: string, idleTtlSeconds: number): Promise<void> {
    const now = new Date();
    await this.sessions.updateOne(
      { realmId, sessionId, terminatedAt: { $exists: false } },
      {
        $set: {
          lastSeenAt: now.toISOString(),
          idleExpiresAt: new Date(now.getTime() + idleTtlSeconds * 1000).toISOString(),
        },
      },
    );
  }

  /**
   * Ends one session, and returns the clients that need telling.
   *
   * The clients come back rather than being notified here, because delivery is a different concern
   * with a different failure mode: a notification that cannot be delivered must not prevent the
   * session from ending.
   */
  async terminate(
    realmId: string,
    sessionId: string,
    reason: SessionRecord['terminationReason'],
    issuer: TokenIssuer,
  ): Promise<{ terminated: boolean; revokedTokens: number; notify: ClientRecord[] }> {
    const session = await this.find(realmId, sessionId);
    if (!session || session.terminatedAt) {
      return { terminated: false, revokedTokens: 0, notify: [] };
    }

    await this.sessions.updateOne(
      { realmId, sessionId },
      { $set: { terminatedAt: new Date().toISOString(), terminationReason: reason } },
    );

    const revokedTokens = await issuer.revokeSession(realmId, sessionId, reason ?? 'logout');

    // The epoch retires a whole generation at once, which covers anything issued under this session
    // that was never recorded here.
    await new DirectoryService(this.db).bumpSessionEpoch(session.subjectId);

    const notify = session.clientIds.length > 0
      ? await this.db
        .collection<ClientRecord>(CLIENT_COLLECTION)
        .find({ realmId, clientId: { $in: session.clientIds } }, { projection: { _id: 0 } })
        .toArray()
      : [];

    return { terminated: true, revokedTokens, notify };
  }

  /**
   * Ends every session a principal holds.
   *
   * What "sign this person out everywhere" means, and the operation that was impossible when a
   * session was an implication rather than a record.
   */
  async terminateAllFor(
    realmId: string,
    subjectId: string,
    reason: SessionRecord['terminationReason'],
    issuer: TokenIssuer,
  ): Promise<{ sessions: number; revokedTokens: number; notify: ClientRecord[] }> {
    const live = await this.listFor(realmId, subjectId);
    let revokedTokens = 0;
    const notify = new Map<string, ClientRecord>();

    for (const session of live) {
      const outcome = await this.terminate(realmId, session.sessionId, reason, issuer);
      revokedTokens += outcome.revokedTokens;
      for (const client of outcome.notify) notify.set(client.clientId, client);
    }

    return { sessions: live.length, revokedTokens, notify: [...notify.values()] };
  }
}
