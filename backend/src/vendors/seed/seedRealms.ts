import { Db } from 'mongodb';
import { REALM_COLLECTION, DOMAIN_COLLECTION } from '../../shared/models/collections';
import { RealmRecord } from '../../modules/realm/models/realm.model';
import { DomainRecord } from '../../modules/realm/models/domain.model';
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
  /** Self-registration. Seeded onto the realm's own directory, which is the only path it can describe. */
  registration?: Partial<NonNullable<DomainRecord['registration']>>;
  tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
  /** Overrides for the realm's own directory, which is a domain now rather than realm config. */
  localAuthentication?: Partial<NonNullable<DomainRecord['authentication']>>;
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

/**
 * Defaults an operator rarely changes, in one place so a fixture states only what is specific to it.
 */
const DEFAULT_TOKEN_POLICY: RealmRecord['tokenPolicy'] = {
  /**
   * Five minutes, and this number IS the revocation objective.
   *
   * An access token is verified against the published key set without touching the database, which
   * is what keeps this authority off the hot path. The cost is that revoking a session cannot reach
   * a token already issued, so the worst case propagation is exactly this lifetime. Fifteen minutes
   * made that window three times longer for no benefit that was ever written down.
   */
  accessTokenTtlSeconds: 300,
  refreshTokenTtlSeconds: 2_592_000,
  codeTtlSeconds: 120,
  sessionIdleTtlSeconds: 3_600,
  sessionMaxTtlSeconds: 43_200,
};

/**
 * The rules for proving identity against a realm's OWN directory.
 *
 * On the local domain rather than on the realm, because that is the path they describe. A realm that
 * also federates has an upstream setting its own, and the two no longer have to pretend to be one.
 */
const DEFAULT_LOCAL_AUTHENTICATION: NonNullable<DomainRecord['authentication']> = {
  passwordPolicy: {
    minLength: 8,
    requireUppercase: false,
    requireNumber: false,
    requireSymbol: false,
    historyDepth: 0,
  },
};

/**
 * The slug every realm's own directory is registered under.
 *
 * `local` said where the directory was rather than what it is, and it read as a developer's word
 * for "not the real one" on a screen a customer sees. This is the realm's OWN directory: the
 * credentials it holds, the policy it enforces and the only path anybody can self-register into.
 *
 * Realm neutral on purpose. Every realm registers one of these, so a slug naming one product would
 * be wrong in the other realm the moment there are two.
 */
const LOCAL_DOMAIN_NAME = 'atlas-id';

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
      {
        name: LOCAL_DOMAIN_NAME,
        displayName: `${fixture.displayName} directory`,
        protocol: 'internal',
        adapter: 'internal',
        enabled: true,
        config: {},
        claimMappings: [],
        authentication: {
          ...DEFAULT_LOCAL_AUTHENTICATION,
          ...fixture.localAuthentication,
        },
        // Unlimited by default: one session per subject produces constant eviction for a person
        // using a laptop, a phone and a tablet.
        session: { maxConcurrent: null, onExceed: 'evict-oldest' },
        /**
         * Self-registration lives HERE and not on the realm (ADR-002).
         *
         * Closed unless a fixture opens it. The internal directory is the only path anybody can
         * join through, so it is the only one this can describe.
         */
        registration: { selfServiceEnabled: false, autoApprove: false, ...fixture.registration },
      },
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
