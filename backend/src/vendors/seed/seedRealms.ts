import { Collection, Db } from 'mongodb';
import { REALM_COLLECTION, DOMAIN_COLLECTION } from '../../shared/models/collections';
import { RealmRecord } from '../../modules/realm/models/realm.model';
import { DomainRecord } from '../../modules/realm/models/domain.model';
import { DEFAULT_TOKEN_POLICY, localDomainRecord } from '../../modules/realm/models/realmDefaults';
import { DEFAULT_TENANT_ID, touchMeta } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';
import { realmIssuer } from '../../config';
import { v5 as uuidv5 } from 'uuid';

/** Stable ids for the domains a realm always has, so a reseed finds them again. */
const DOMAIN_NAMESPACE = 'd0a7c3e1-5b92-4f18-9c64-8e3a1f7b2d05';

/**
 * The realms, and every authentication domain inside each of them.
 *
 * Read from a fixture rather than written here, so adding a realm is data and this file stays
 * industry neutral: nothing in it names a consuming application. The fixture that does name one is
 * the deployment's, not the product's.
 */

interface DomainFixture {
  /**
   * Optional. Absent means a stable id derived from the realm and the slug, which is what the
   * realm's own directory uses: it is created by every realm rather than written out in each
   * fixture, and deriving it keeps the id the same across reseeds without anybody maintaining it.
   */
  domainId?: string;
  name: string;
  displayName?: string;
  protocol: DomainRecord['protocol'];
  adapter: string;
  enabled?: boolean;
  notice?: string;
  config?: DomainRecord['config'];
  claimMappings?: DomainRecord['claimMappings'];
  /** Meaningful for `internal`. A federated path's upstream owns these rules. */
  authentication?: Partial<NonNullable<DomainRecord['authentication']>>;
  /** Self-service joining, which only an internal path can describe. */
  registration?: Partial<NonNullable<DomainRecord['registration']>>;
}

interface RealmFixture {
  realmId: string;
  name: string;
  displayName: string;
  aliases?: string[];
  notice?: string;
  enabled?: boolean;
  demoMode?: boolean;
  clientEnforcement?: RealmRecord['clientEnforcement'];
  requiresElevationApproval?: RealmRecord['requiresElevationApproval'];
  tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
  /**
   * Only what OVERRIDES the realm's own name and nothing that restates it. `displayName` here is
   * absent unless the rendered label genuinely differs.
   */
  branding?: Partial<RealmRecord['branding']>;
  /**
   * Every authentication path into this realm, INCLUDING the realm's own directory.
   *
   * Flat on purpose. The internal path used to be described by `localDomainDisplayName`,
   * `localAuthentication` and `registration` sitting on the realm while the federated ones sat in
   * an array beside them, which read as though the realm's own directory were a property of the
   * realm rather than one domain among others. It is one domain among others, and the fixture now
   * says so. Exactly one entry must have `protocol: "internal"`.
   */
  domains: DomainFixture[];
}

export async function seedRealms(db: Db): Promise<void> {
  const fixtures = readSeedFile<RealmFixture[]>('realms.json');
  const realms = db.collection<RealmRecord>(REALM_COLLECTION);
  const providers = db.collection<DomainRecord>(DOMAIN_COLLECTION);

  for (const fixture of fixtures) {
    // The issuer is COMPOSED from the deployment's public URL, never stored in a fixture. A fixture
    // carrying a hostname only works in the deployment it was written for.
    const issuer = realmIssuer(fixture.name);

    const realm = await upsertSeed(
      realms,
      { realmId: fixture.realmId },
      {
        name: fixture.name,
        displayName: fixture.displayName,
        issuer,
        enabled: fixture.enabled ?? true,
        aliases: fixture.aliases ?? [],
        ...(fixture.notice ? { notice: fixture.notice } : {}),
        tokenPolicy: { ...DEFAULT_TOKEN_POLICY, ...fixture.tokenPolicy },
        // No `displayName` copied in. It is only present when the fixture states an override, so
        // the realm's own name stays the single place the label comes from (see `brandLabel`).
        branding: { ...fixture.branding },
        demoMode: fixture.demoMode ?? false,
        // Absent in the fixture means the realm inherits the deployment default, which is strict.
        ...(fixture.clientEnforcement ? { clientEnforcement: fixture.clientEnforcement } : {}),
        // Absent in the fixture means a requested elevation needs a second approver, which is the
        // safer default (see RealmRecord.requiresElevationApproval).
        ...(fixture.requiresElevationApproval !== undefined
          ? { requiresElevationApproval: fixture.requiresElevationApproval } : {}),
      },
      // A realm is its own partition. tenantId survives as a field so the partition key and the
      // option of a real second tenant are preserved; only the tenant collection is gone.
      { realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID },
      'Realm',
    );
    console.log(`  realm:    ${fixture.name} (${issuer}) ${realm.action}`);

    /**
     * Every domain the fixture declares, the realm's own directory included.
     *
     * P8.3 held that every realm gets exactly one internal domain. That is still true, and it is
     * now CHECKED rather than manufactured: the fixture declares it beside the federated paths and
     * this refuses a realm that declares none or more than one. Manufacturing it here is what made
     * the internal path look like a property of the realm.
     */
    const internal = fixture.domains.filter((domain) => domain.protocol === 'internal');
    if (internal.length !== 1) {
      throw new Error(
        `realm "${fixture.name}" declares ${internal.length} internal domains, and needs exactly one`,
      );
    }

    for (const domain of fixture.domains) {
      // Derived when the fixture omits it, which is how the realm's own directory keeps the id it
      // has always had without that id being written out by hand in every fixture.
      const domainId = domain.domainId ?? uuidv5(`domain:${fixture.realmId}:${domain.name}`, DOMAIN_NAMESPACE);
      const scope = { domainId, realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID };

      /**
       * The internal path goes through the shared builder, the federated ones do not.
       *
       * Not a special case in the MODEL, which is the distinction that matters: both end up as one
       * record in one collection, read by the same code. The builder exists because a realm created
       * at runtime has no fixture to read defaults from, and the two paths must agree on what a
       * freshly provisioned directory looks like.
       */
      const record: Omit<DomainRecord, 'meta'> = domain.protocol === 'internal'
        ? localDomainRecord({
          ...scope,
          name: domain.name,
          realmDisplayName: fixture.displayName,
          domainDisplayName: domain.displayName,
          authentication: domain.authentication,
          registration: domain.registration && {
            selfServiceEnabled: false, autoApprove: false, ...domain.registration,
          },
        })
        : {
          ...scope,
          name: domain.name,
          displayName: domain.displayName ?? domain.name,
          protocol: domain.protocol,
          adapter: domain.adapter,
          // A federated path is off until somebody says otherwise: its configuration is usually
          // incomplete in a fixture, and offering it would fail after it is chosen.
          enabled: domain.enabled ?? false,
          ...(domain.notice ? { notice: domain.notice } : {}),
          config: domain.config ?? {},
          claimMappings: domain.claimMappings ?? [],
        };

      // `realmId` and `tenantId` are in `record`, and repeated as the scope `upsertSeed` writes on
      // an insert. Spreading `record` here would make the update path rewrite them, which is the
      // one thing a reseed must never move a domain between.
      const { realmId: _realm, tenantId: _tenant, domainId: _id, ...changes } = record;
      const outcome = await upsertSeed<DomainRecord>(providers, { domainId }, changes, scope, 'Domain');
      console.log(`  domain:   ${fixture.name}/${domain.name} (${domain.protocol}) ${outcome.action}`);
    }
  }

  await recomposeIssuers(realms);
}

/**
 * Every persisted realm's issuer, composed again from its name.
 *
 * The fixture loop above only reaches realms a fixture declares; a realm created at runtime
 * (`POST /api/v1/realms`) keeps whatever issuer it was stored with. The issuer is always derived
 * (`realmIssuer(name)`, and a realm cannot be renamed), so a stored one that differs is stale: after
 * the address scheme moved under `/api/v1`, it pointed at routes that no longer exist. Idempotent,
 * so a reseed is also the upgrade. Tokens minted under the old issuer stop validating, which is
 * the release's documented breaking change: holders sign in again.
 */
export async function recomposeIssuers(realms: Collection<RealmRecord>): Promise<void> {
  const stored = await realms
    .find({}, { projection: { _id: 0, realmId: 1, name: 1, issuer: 1, meta: 1 } })
    .toArray();
  for (const realm of stored) {
    const issuer = realmIssuer(realm.name);
    if (realm.issuer === issuer) continue;
    await realms.updateOne(
      { realmId: realm.realmId },
      { $set: { issuer, ...(realm.meta ? { meta: touchMeta(realm.meta) } : {}) } },
    );
    console.log(`  realm:    ${realm.name} issuer ${realm.issuer} -> ${issuer}`);
  }
}
