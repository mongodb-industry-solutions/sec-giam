import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { REALM_COLLECTION, DOMAIN_COLLECTION, CASE_INSENSITIVE } from '../../../shared/models/collections';
import { DEFAULT_TENANT_ID, newMeta, touchMeta } from '../../../shared/models/base.model';
import { RealmRecord } from '../models/realm.model';
import { DomainRecord, selfRegistration } from '../models/domain.model';
import { DEFAULT_TOKEN_POLICY, localDomainRecord } from '../models/realmDefaults';
import { realmIssuer } from '../../../config';
import { KeyRing } from '../../keys/services/keyRing.service';
import { MongoSigningKeyStore } from '../../keys/services/signingKeyStore';
import { keyProviders } from '../../../shared/ports';
import { config } from '../../../config';

export type RealmRefusal = { status: number; title: string; detail: string };

export function isRealmRefusal(value: unknown): value is RealmRefusal {
  return typeof value === 'object' && value !== null && 'status' in value && 'title' in value;
}

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
    return this.db.collection<DomainRecord>(DOMAIN_COLLECTION);
  }

  async byId(realmId: string): Promise<RealmRecord | null> {
    return this.realms.findOne({ realmId }, { projection: { _id: 0 } });
  }

  /**
   * By name or by any alias it answers to, WITHOUT case. Disabled realms resolve, so callers can
   * say why rather than answering "no such realm" to a realm that plainly exists.
   *
   * One indexed query for both. It used to lowercase the input, try an exact match, and on a miss
   * LOAD EVERY REALM and compare them in memory: correct, and a full collection read on the miss
   * path, which is the path every request took the moment a realm's own name carried a capital
   * letter. `name_unique` and `aliases` are declared with the same collation, so this is an index
   * lookup for both branches of the `$or`.
   *
   * The trim stays, because a name arriving with whitespace is a caller's mistake rather than a
   * different realm. The lowercasing is gone: that was this code doing the collation's job, badly,
   * since it could only ever match a stored name that was already lower case.
   */
  async byName(name: string): Promise<RealmRecord | null> {
    const wanted = name.trim();
    if (!wanted) return null;
    return this.realms.findOne(
      { $or: [{ name: wanted }, { aliases: wanted }] },
      { projection: { _id: 0 }, collation: CASE_INSENSITIVE },
    );
  }

  /** The realm a token claims to come from, resolved from its issuer. */
  async byIssuer(issuer: string): Promise<RealmRecord | null> {
    return this.realms.findOne({ issuer }, { projection: { _id: 0 } });
  }

  async list(): Promise<RealmRecord[]> {
    return this.realms.find({}, { projection: { _id: 0 } }).sort({ name: 1 }).toArray();
  }

  async providersFor(realmId: string): Promise<DomainRecord[]> {
    return this.providers.find({ realmId }, { projection: { _id: 0 } }).sort({ name: 1 }).toArray();
  }

  /**
   * The realm's own directory, as a domain.
   *
   * Every realm has exactly one, created at seed time, which is what lets local authentication
   * resolve through a domain like every other path rather than through a branch only it takes. It
   * carries the password rules and the concurrent-session limit for that path.
   */
  async localDomain(realmId: string): Promise<DomainRecord | null> {
    return this.providers.findOne(
      { realmId, protocol: 'internal' },
      { projection: { _id: 0 } },
    );
  }

  /**
   * Whether this realm accepts self-registration, and whether it approves automatically.
   *
   * ADR-002 moved this off the realm and onto the path that does the proving, so it is resolved
   * from the internal directory rather than read off the realm record. Nobody self-registers into
   * a federated upstream, so a realm without an ENABLED internal path has nowhere for a
   * self-registered credential to live and the answer is no.
   *
   * `enabled` is required here and deliberately not in `localDomain`: a disabled path still owns
   * the password policy that describes it, and is still not somewhere to join.
   */
  async registration(realmId: string): Promise<{ selfServiceEnabled: boolean; autoApprove: boolean }> {
    const local = await this.providers.findOne(
      { realmId, protocol: 'internal', enabled: true },
      { projection: { _id: 0, registration: 1 } },
    );
    return selfRegistration(local);
  }

  /**
   * Home-realm discovery: which provider should authenticate the address the user typed.
   *
   * Returns null when nothing claims the domain, and the caller then shows a picker. Guessing would
   * be worse than asking: sending someone to the wrong identity provider produces a failure they
   * cannot interpret and cannot fix.
   */
  async providerForEmail(realmId: string, email: string): Promise<DomainRecord | null> {
    const domain = email.split('@')[1]?.trim().toLowerCase();
    if (!domain) return null;
    return this.providers.findOne(
      { realmId, enabled: true, 'config.emailDomains': domain },
      { projection: { _id: 0 } },
    );
  }

  /**
   * Provisions a new realm: its own trust and key boundary, ready to sign in against immediately.
   *
   * Does exactly what `seedRealms` does for one realm, on demand, reusing the same defaults
   * (`realmDefaults.ts`) so a realm created here and one created by a reseed can never drift into
   * looking like two different things. Three parts, none optional, because a realm missing any one
   * of them is not a smaller realm, it is a broken one:
   *
   * 1. The realm record itself (issuer, token policy, branding).
   * 2. Its own internal domain, so it has somewhere for a principal to belong to (P43's own
   *    invariant: no principal exists without one).
   * 3. A published signing key, so it can mint a token immediately rather than failing on first use
   *    with an error that reads as a token bug rather than as an unseeded key set.
   */
  async create(input: {
    name: string;
    displayName: string;
    notice?: string;
    branding?: Partial<RealmRecord['branding']>;
    tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
    demoMode?: boolean;
    clientEnforcement?: RealmRecord['clientEnforcement'];
  }): Promise<RealmRecord | RealmRefusal> {
    /**
     * Kept AS TYPED, capitals included, and checked for clashes without case.
     *
     * It used to be lower-cased here, which refused a name the seeder itself uses (`LeafyIdp`) and
     * meant the API could not create the realm the fixture creates. Casing a slug is a legitimate
     * choice about how a product's name reads in an issuer URL, and it is not this function's to
     * make. What must not happen is TWO realms differing only by case, and that is now prevented
     * where it belongs: `byName` resolves without case and `name_unique` refuses the insert.
     */
    const name = input.name.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(name)) {
      return {
        status: 400,
        title: 'Not a valid realm name',
        detail: 'Letters, digits and dashes, starting with a letter or digit. It becomes part of the issuer URL, and two realms may not differ only by case.',
      };
    }
    if (await this.byName(name)) {
      return {
        status: 409,
        title: 'That realm already exists',
        detail: `"${name}" is already the name or an alias of a realm. Names identify a realm in every token it issues, so two of them would make verification ambiguous.`,
      };
    }

    const realmId = uuidv4();
    const record: RealmRecord = {
      realmId,
      tenantId: DEFAULT_TENANT_ID,
      name,
      displayName: input.displayName,
      issuer: realmIssuer(name),
      enabled: true,
      aliases: [],
      ...(input.notice ? { notice: input.notice } : {}),
      tokenPolicy: { ...DEFAULT_TOKEN_POLICY, ...input.tokenPolicy },
      // Only the overrides. `branding.displayName` stays absent unless the caller asked for a
      // label different from the realm's own name, so the two can never disagree (`brandLabel`).
      branding: { ...input.branding },
      demoMode: input.demoMode ?? false,
      ...(input.clientEnforcement ? { clientEnforcement: input.clientEnforcement } : {}),
      meta: newMeta('Realm'),
    };
    await this.realms.insertOne(record);

    const domainId = uuidv4();
    await this.providers.insertOne({
      ...localDomainRecord({
        domainId,
        realmId,
        tenantId: DEFAULT_TENANT_ID,
        realmDisplayName: input.displayName,
      }),
      meta: newMeta('Domain'),
    } as DomainRecord);

    const provider = keyProviders.resolve(config.keys.provider);
    await new KeyRing(new MongoSigningKeyStore(this.db), provider).publishOwnKey(realmId, DEFAULT_TENANT_ID);

    return record;
  }

  /**
   * Changes what an operator may actually reconsider after creation.
   *
   * `name` is deliberately not here: it is embedded in the issuer URL and is what every existing
   * token, alias and lookup already resolved on, so changing it is a new realm wearing an old one's
   * identifier, not an edit. `realmId`, `issuer` and `aliases` are the same kind of thing.
   */
  async update(realmId: string, patch: {
    displayName?: string;
    enabled?: boolean;
    notice?: string;
    branding?: Partial<RealmRecord['branding']>;
    tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
    demoMode?: boolean;
    clientEnforcement?: RealmRecord['clientEnforcement'];
  }): Promise<RealmRecord | null> {
    const realm = await this.byId(realmId);
    if (!realm) return null;

    const changes: Partial<RealmRecord> = {};
    if (patch.displayName !== undefined) changes.displayName = patch.displayName;
    if (patch.enabled !== undefined) changes.enabled = patch.enabled;
    if (patch.notice !== undefined) changes.notice = patch.notice;
    if (patch.branding) changes.branding = { ...realm.branding, ...patch.branding };
    if (patch.tokenPolicy) changes.tokenPolicy = { ...realm.tokenPolicy, ...patch.tokenPolicy };
    if (patch.demoMode !== undefined) changes.demoMode = patch.demoMode;
    if (patch.clientEnforcement !== undefined) changes.clientEnforcement = patch.clientEnforcement;

    if (Object.keys(changes).length > 0) {
      await this.realms.updateOne({ realmId }, { $set: { ...changes, meta: touchMeta(realm.meta) } });
    }
    return this.byId(realmId);
  }
}
