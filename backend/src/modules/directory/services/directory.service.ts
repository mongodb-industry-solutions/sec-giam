import { Db } from 'mongodb';
import { PRINCIPAL_COLLECTION, CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { PrincipalRecord, canAuthenticate } from '../models/principal.model';
import { CredentialRecord, CredentialType, isUsable } from '../models/credential.model';

/**
 * Reading principals and their credentials.
 *
 * Every lookup is realm-scoped, without exception. A subject is unique globally, but a USER NAME is
 * unique only inside a realm, so a query that forgot the realm would resolve one institution's user
 * from another institution's login form, and would do it silently.
 */
export class DirectoryService {
  constructor(private readonly db: Db) {}

  private get identities() {
    return this.db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION);
  }

  private get credentials() {
    return this.db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
  }

  async findBySubjectId(subjectId: string): Promise<PrincipalRecord | null> {
    return this.identities.findOne({ subjectId }, { projection: { _id: 0 } });
  }

  /**
   * The principal bound to a business reference.
   *
   * The authority does not know what the reference names and never resolves it against anything.
   * What it can answer is which principal was bound to it, which is what lets a consuming
   * application ask about a person it knows by its own identifier without holding a copy of the
   * mapping, and without this service learning what the identifier means.
   */
  async findByAccountHolderRef(realmId: string, accountHolderRef: string): Promise<PrincipalRecord | null> {
    return this.identities.findOne({ realmId, accountHolderRef }, { projection: { _id: 0 } });
  }

  /**
   * Subject ids to the names behind them, for a whole response at once.
   *
   * Administrative screens list SESSIONS, ROLE ASSIGNMENTS and ELEVATIONS, and every one of those
   * is about a person. They were rendering `a1000070-0000-4000-8000-000000000070`, which is
   * unreadable at a glance and unusable as a way to recognise who a row is about.
   *
   * A batch rather than a lookup per row: a page of a hundred sessions held by a handful of people
   * is one query here and a hundred there. Absent ids are simply absent from the map, and a caller
   * falls back to the id rather than inventing a name for a principal that no longer exists.
   */
  async namesFor(realmId: string, subjectIds: ReadonlyArray<string>): Promise<Map<string, string>> {
    const wanted = [...new Set(subjectIds.filter(Boolean))];
    if (wanted.length === 0) return new Map();

    const found = await this.identities
      .find(
        { realmId, subjectId: { $in: wanted } },
        { projection: { _id: 0, subjectId: 1, userName: 1 } },
      )
      .toArray();
    return new Map(found.map((identity) => [identity.subjectId, identity.userName]));
  }

  async findByUserName(realmId: string, userName: string): Promise<PrincipalRecord | null> {
    return this.identities.findOne({ realmId, userName }, { projection: { _id: 0 } });
  }

  /**
   * Resolve a principal from whatever the user typed.
   *
   * The user name first, then the email. Both are ways of naming the same person, and asking someone
   * to remember which one a system wants is an avoidable failure.
   */
  async findByLogin(realmId: string, login: string): Promise<PrincipalRecord | null> {
    const trimmed = login.trim();
    if (!trimmed) return null;
    const byUserName = await this.findByUserName(realmId, trimmed);
    if (byUserName) return byUserName;
    // Equality over ciphertext: the encrypted index makes this a lookup rather than a scan.
    return this.identities.findOne(
      { realmId, primaryEmail: trimmed.toLowerCase() },
      { projection: { _id: 0 } },
    );
  }

  /**
   * Every credential this principal holds, of any type and any status.
   *
   * Unlike `credentialsFor`, nothing is filtered out: a revoked authenticator and a suspended one are
   * exactly what an oversight review needs to see, not just what would currently authenticate. Sorted
   * newest first, so the credential somebody is asking about is usually near the top.
   */
  async allCredentialsFor(realmId: string, subjectId: string): Promise<CredentialRecord[]> {
    return this.credentials
      .find({ realmId, subjectId }, { projection: { _id: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
  }

  async credentialsFor(subjectId: string, type: CredentialType): Promise<CredentialRecord[]> {
    const held = await this.credentials
      .find({ subjectId, type, status: 'active' }, { projection: { _id: 0 } })
      .toArray();
    // Expiry is judged here rather than in the query, so a credential that lapsed a second ago is
    // refused by the same rule that refuses one that lapsed a year ago.
    return held.filter((credential) => isUsable(credential));
  }

  /** The roster the sign-in screen offers, in a deterministic order so the demo is repeatable. */
  async demoRoster(realmId: string): Promise<PrincipalRecord[]> {
    return this.identities
      .find({ realmId, demoFeatured: true }, { projection: { _id: 0 } })
      .sort({ userName: 1 })
      .toArray();
  }

  async isDemoFeatured(subjectId: string): Promise<boolean> {
    const identity = await this.findBySubjectId(subjectId);
    return Boolean(identity?.demoFeatured);
  }

  /**
   * Invalidate every token issued before now, without listing them.
   *
   * The epoch travels in the token, so raising it retires a whole generation at once. That is what
   * makes "sign out everywhere" a single write rather than a search for outstanding credentials.
   */
  /**
   * Retires every token issued to this principal before now, without listing them.
   *
   * Two round trips rather than one findOneAndUpdate, because queryable encryption does not support
   * findAndModify on an encrypted collection. That is not a detail worth hiding: written the obvious
   * way, this threw at runtime and turned every logout into a 500, while the session was left
   * terminated. A sign-out that half succeeds is worse than one that fails, because the person
   * believes they are out.
   *
   * The read-after-write is not atomic and does not need to be. The increment is, and the returned
   * value is only reported; nothing decides anything on it.
   */
  async bumpSessionEpoch(subjectId: string): Promise<number> {
    await this.identities.updateOne({ subjectId }, { $inc: { sessionEpoch: 1 } });
    const updated = await this.identities.findOne(
      { subjectId },
      { projection: { _id: 0, sessionEpoch: 1 } },
    );
    return updated?.sessionEpoch ?? 0;
  }

  /** Whether this principal may authenticate at all, before any credential is examined. */
  async isAuthenticatable(subjectId: string): Promise<boolean> {
    const identity = await this.findBySubjectId(subjectId);
    return Boolean(identity && canAuthenticate(identity));
  }
}
