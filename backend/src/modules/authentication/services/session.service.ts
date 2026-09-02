import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { newMeta } from '../../../shared/models/base.model';
import { SESSION_COLLECTION } from '../../../shared/models/collections';
import { SessionRecord, isLive } from '../models/session.model';

/**
 * Why a session ended.
 *
 * Not stored on the session, which is deleted, but carried into the audit record, which is
 * where the history lives. A reason on a deleted document would be a reason nobody can read.
 */
export type SessionReason = 'logout' | 'expired' | 'revoked' | 'superseded';
import { DirectoryService } from '../../directory/services/directory.service';
import { TokenIssuer } from '../../oauth/services/tokenIssuer.service';
import { OAuthClient } from '../../oauth/models/client.model';
import { listOAuthClients } from '../../oauth/services/clientAuth.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';

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
    clientId?: string;
    domainId?: string;
    authRequestId?: string;
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
      // Starts at zero and is incremented per refresh. The refresh JWT carries the generation it
      // was minted at, and a mismatch is how a replay is detected.
      refreshGen: 0,
      ...(input.clientId ? { clientId: input.clientId } : {}),
      ...(input.domainId ? { domainId: input.domainId } : {}),
      ...(input.authRequestId ? { authRequestId: input.authRequestId } : {}),
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

    // Recorded here rather than in each controller, for the same reason the record is built here: a
    // federated sign-in and a password one must leave the same evidence, not two that drift.
    void new SecurityEventService(this.db).record({
      realmId: session.realmId,
      tenantId: session.tenantId,
      category: 'session',
      action: 'authentication.session.created',
      outcome: 'success',
      subjectId: session.subjectId,
      target: { type: 'session', ref: session.sessionId },
      ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      detail: { expiresAt: session.expiresAt },
    });
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

  /**
   * Every live session in a realm, for an administrator rather than for one person.
   *
   * Terminated ones are excluded rather than shown greyed out: the question this answers is "who is
   * signed in right now", and a list mixing the two invites ending something that already ended.
   */
  async listForRealm(
    realmId: string,
    options: { skip?: number; limit?: number } = {},
  ): Promise<{ sessions: SessionRecord[]; total: number }> {
    const filter = { realmId, terminatedAt: { $exists: false } };
    const held = await this.sessions
      .find(filter, { projection: { _id: 0 } })
      .sort({ lastSeenAt: -1 })
      .toArray();
    // Expiry is judged here rather than left to the sweep, so the total and the page agree with each
    // other: counting in the database and filtering in memory would disagree by whatever the sweep
    // has not reached yet.
    const live = held.filter((session) => isLive(session));
    const skip = Math.max(0, options.skip ?? 0);
    return {
      sessions: live.slice(skip, skip + Math.min(options.limit ?? 20, 200)),
      total: live.length,
    };
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
    reason: SessionReason,
    issuer: TokenIssuer,
  ): Promise<{ terminated: boolean; revokedTokens: number; notify: OAuthClient[] }> {
    const session = await this.find(realmId, sessionId);
    if (!session) {
      return { terminated: false, revokedTokens: 0, notify: [] };
    }

    // The clients are read BEFORE the delete, because after it there is no record to read them
    // from. That ordering is the whole reason this is not a one-line delete.
    const notifyIds = session.clientIds;

    /**
     * DELETED, not marked.
     *
     * The absence of the document is the revocation signal. A record left behind marked terminated
     * is a record some query will forget to filter, and the filter being forgotten is exactly how a
     * revoked session keeps working. Absence cannot be forgotten.
     */
    await this.sessions.deleteOne({ realmId, sessionId });

    // Nothing to revoke: no token was ever written down. The count stays in the response because
    // callers report it, and zero is the honest answer now.
    const revokedTokens = 0;

    // The epoch retires a whole generation at once, which covers anything issued under this session
    // that was never recorded here.
    const epoch = await new DirectoryService(this.db).bumpSessionEpoch(session.subjectId);

    // Recorded HERE rather than inside the directory, which is where the realm and the tenant are
    // known. Raising the epoch invalidates every outstanding token this principal holds, including
    // ones from other sessions and ones this authority never wrote down, so it is a mass revocation
    // and the widest-reaching thing ending a session does. Leaving it unrecorded meant the trail
    // could show a single sign-out and nothing about the tokens it silently retired.
    void new SecurityEventService(this.db).record({
      realmId: session.realmId,
      tenantId: session.tenantId,
      category: 'session',
      action: 'authentication.session.epoch_raised',
      outcome: 'success',
      subjectId: session.subjectId,
      target: { type: 'session', ref: sessionId },
      detail: { epoch, reason: reason ?? 'logout', revokedTokens },
    });

    const notify = notifyIds.length > 0
      ? (await listOAuthClients(this.db, realmId)).filter((client) => notifyIds.includes(client.clientId))
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
    reason: SessionReason,
    issuer: TokenIssuer,
  ): Promise<{ sessions: number; revokedTokens: number; notify: OAuthClient[] }> {
    const live = await this.listFor(realmId, subjectId);
    let revokedTokens = 0;
    const notify = new Map<string, OAuthClient>();

    for (const session of live) {
      const outcome = await this.terminate(realmId, session.sessionId, reason, issuer);
      revokedTokens += outcome.revokedTokens;
      for (const client of outcome.notify) notify.set(client.clientId, client);
    }

    return { sessions: live.length, revokedTokens, notify: [...notify.values()] };
  }
}
