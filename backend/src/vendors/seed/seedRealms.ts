import { Db } from 'mongodb';
import { REALM_COLLECTION, DOMAIN_COLLECTION } from '../../shared/models/collections';
import { RealmRecord } from '../../modules/realm/models/realm.model';
import { DomainRecord } from '../../modules/realm/models/domain.model';
import { DEFAULT_TOKEN_POLICY, LOCAL_DOMAIN_NAME, localDomainRecord } from '../../modules/realm/models/realmDefaults';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';
import { realmIssuer } from '../../config';
import { v5 as uuidv5 } from 'uuid';

/** Stable ids for the domains a realm always has, so a reseed finds them again. */
const DOMAIN_NAMESPACE = 'd0a7c3e1-5b92-4f18-9c64-8e3a1f7b2d05';

/**
 * The realms and the providers federated inside them.
 *
 * Read from a fixture rather than written here, so adding a realm is data and this file stays
 * industry neutral: nothing in it names a consuming application. The fixture that does name one is
 * the deployment's, not the product's.
 */

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
  /** Self-registration. Seeded onto the realm's own directory, which is the only path it can describe. */
  registration?: Partial<NonNullable<DomainRecord['registration']>>;
  tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
  /** Overrides for the realm's own directory, which is a domain now rather than realm config. */
  localAuthentication?: Partial<NonNullable<DomainRecord['authentication']>>;
  /** Overrides the generic `"{realm} directory"` label the local domain otherwise gets. */
  localDomainDisplayName?: string;
  branding?: Partial<RealmRecord['branding']>;
  providers?: Array<{
    domainId: string;
    name: string;
    displayName: string;
    protocol: DomainRecord['protocol'];
    adapter: string;
    enabled?: boolean;
    notice?: string;
    config?: DomainRecord['config'];
    claimMappings?: DomainRecord['claimMappings'];
  }>;
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
        branding: { displayName: fixture.displayName, ...fixture.branding },
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
     * P8.3. Every realm gets ONE local domain, always.
     *
     * Local authentication then resolves through a domain like every other path, instead of through
     * a branch on the realm that only the local case takes. A realm with one domain shows no
     * chooser on the sign-in screen, which is a presentation decision rather than a model one.
     */
    const localId = uuidv5(`domain:${fixture.realmId}:${LOCAL_DOMAIN_NAME}`, DOMAIN_NAMESPACE);
    const local = await upsertSeed<DomainRecord>(
      providers,
      { domainId: localId },
      localDomainRecord({
        domainId: localId,
        realmId: fixture.realmId,
        tenantId: DEFAULT_TENANT_ID,
        realmDisplayName: fixture.displayName,
        domainDisplayName: fixture.localDomainDisplayName,
        authentication: fixture.localAuthentication,
        registration: fixture.registration && { selfServiceEnabled: false, autoApprove: false, ...fixture.registration },
      }),
      { domainId: localId, realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID },
      'Domain',
    );
    console.log(`  domain:   ${fixture.name}/${LOCAL_DOMAIN_NAME} (internal) ${local.action}`);

    for (const provider of fixture.providers ?? []) {
      const outcome = await upsertSeed(
        providers,
        { domainId: provider.domainId },
        {
          name: provider.name,
          displayName: provider.displayName,
          protocol: provider.protocol,
          adapter: provider.adapter,
          enabled: provider.enabled ?? false,
          ...(provider.notice ? { notice: provider.notice } : {}),
          config: provider.config ?? {},
          claimMappings: provider.claimMappings ?? [],
        },
        // Inside the realm, not beside it. This is the split the platform's old model conflated.
        { domainId: provider.domainId, realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID },
        'Domain',
      );
      console.log(`  domain:   ${fixture.name}/${provider.name} (${provider.protocol}) ${outcome.action}`);
    }
  }
}
