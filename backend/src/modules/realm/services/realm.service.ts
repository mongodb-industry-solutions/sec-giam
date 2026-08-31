import { Db } from 'mongodb';
import { REALM_COLLECTION, IDENTITY_PROVIDER_COLLECTION } from '../../../shared/models/collections';
import { RealmRecord, matchesRealmName } from '../models/realm.model';
import { IdentityProviderRecord } from '../models/identityProvider.model';

/**
 * Resolving realms and the providers federated inside them.
 *
 * A realm is resolved by NAME on the wire, because that is what appears in an issuer URL and in a
 * login form, and by alias too: the platform used to special-case one alias in a resolver, and here
 * it is a value on the record it belongs to, so adding another is data.
 */
export class RealmService {
  constructor(private readonly db: Db) {}

  private get realms() {
    return this.db.collection<RealmRecord>(REALM_COLLECTION);
  }

  private get providers() {
    return this.db.collection<IdentityProviderRecord>(IDENTITY_PROVIDER_COLLECTION);
  }

  async byId(realmId: string): Promise<RealmRecord | null> {
    return this.realms.findOne({ realmId }, { projection: { _id: 0 } });
  }

  /** By name or by any alias it answers to. Disabled realms resolve, so callers can say why. */
  async byName(name: string): Promise<RealmRecord | null> {
    const wanted = name.trim().toLowerCase();
    if (!wanted) return null;
    const direct = await this.realms.findOne({ name: wanted }, { projection: { _id: 0 } });
    if (direct) return direct;
    const all = await this.realms.find({}, { projection: { _id: 0 } }).toArray();
    return all.find((realm) => matchesRealmName(realm, wanted)) ?? null;
  }

  /** The realm a token claims to come from, resolved from its issuer. */
  async byIssuer(issuer: string): Promise<RealmRecord | null> {
    return this.realms.findOne({ issuer }, { projection: { _id: 0 } });
  }

  async list(): Promise<RealmRecord[]> {
    return this.realms.find({}, { projection: { _id: 0 } }).sort({ name: 1 }).toArray();
  }

  async providersFor(realmId: string): Promise<IdentityProviderRecord[]> {
    return this.providers.find({ realmId }, { projection: { _id: 0 } }).sort({ name: 1 }).toArray();
  }

  /**
   * Home-realm discovery: which provider should authenticate the address the user typed.
   *
   * Returns null when nothing claims the domain, and the caller then shows a picker. Guessing would
   * be worse than asking: sending someone to the wrong identity provider produces a failure they
   * cannot interpret and cannot fix.
   */
  async providerForEmail(realmId: string, email: string): Promise<IdentityProviderRecord | null> {
    const domain = email.split('@')[1]?.trim().toLowerCase();
    if (!domain) return null;
    return this.providers.findOne(
      { realmId, enabled: true, 'config.emailDomains': domain },
      { projection: { _id: 0 } },
    );
  }
}
