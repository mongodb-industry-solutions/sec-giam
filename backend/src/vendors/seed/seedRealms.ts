import { Db } from 'mongodb';
import { REALM_COLLECTION, TENANT_COLLECTION, IDENTITY_PROVIDER_COLLECTION } from '../../shared/models/collections';
import { RealmRecord } from '../../modules/realm/models/realm.model';
import { IdentityProviderRecord } from '../../modules/realm/models/identityProvider.model';
import { TenantRecord } from '../../modules/directory/models/tenant.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';
import { realmIssuer } from '../../config';

/**
 * The realms, their default tenants and the providers federated inside them.
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
  registration?: Partial<RealmRecord['registration']>;
  tokenPolicy?: Partial<RealmRecord['tokenPolicy']>;
  passwordPolicy?: Partial<RealmRecord['passwordPolicy']>;
  branding?: Partial<RealmRecord['branding']>;
  tenants?: Array<{ tenantId: string; name: string; displayName: string; parentTenantId?: string }>;
  providers?: Array<{
    providerId: string;
    name: string;
    displayName: string;
    protocol: IdentityProviderRecord['protocol'];
    adapter: string;
    enabled?: boolean;
    notice?: string;
    config?: IdentityProviderRecord['config'];
    claimMappings?: IdentityProviderRecord['claimMappings'];
  }>;
}

/**
 * Defaults an operator rarely changes, in one place so a fixture states only what is specific to it.
 *
 * Fifteen minutes on an access token is the revocation window the decentralised validation model
 * trades for its independence. It is short deliberately: it bounds how long a revoked token stays
 * usable when the revocation stream has not reached a resource server yet.
 */
const DEFAULT_TOKEN_POLICY: RealmRecord['tokenPolicy'] = {
  accessTokenTtlSeconds: 900,
  refreshTokenTtlSeconds: 2_592_000,
  codeTtlSeconds: 120,
  sessionIdleTtlSeconds: 3_600,
  sessionMaxTtlSeconds: 43_200,
};

const DEFAULT_PASSWORD_POLICY: RealmRecord['passwordPolicy'] = {
  minLength: 8,
  requireUppercase: false,
  requireNumber: false,
  requireSymbol: false,
  historyDepth: 0,
};

export async function seedRealms(db: Db): Promise<void> {
  const fixtures = readSeedFile<RealmFixture[]>('realms.json');
  const realms = db.collection<RealmRecord>(REALM_COLLECTION);
  const tenants = db.collection<TenantRecord>(TENANT_COLLECTION);
  const providers = db.collection<IdentityProviderRecord>(IDENTITY_PROVIDER_COLLECTION);

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
        registration: { selfServiceEnabled: false, autoApprove: false, ...fixture.registration },
        tokenPolicy: { ...DEFAULT_TOKEN_POLICY, ...fixture.tokenPolicy },
        passwordPolicy: { ...DEFAULT_PASSWORD_POLICY, ...fixture.passwordPolicy },
        branding: { displayName: fixture.displayName, ...fixture.branding },
        demoMode: fixture.demoMode ?? false,
      },
      // A realm is its own partition, and its own record sits in its default tenant.
      { realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID },
      'Realm',
    );
    console.log(`  realm:    ${fixture.name} (${issuer}) ${realm.action}`);

    // Every realm gets a tenant, so no record ever carries an empty partition and no query needs a
    // branch for the single-tenant case.
    const tenantFixtures = fixture.tenants ?? [{
      tenantId: DEFAULT_TENANT_ID,
      name: DEFAULT_TENANT_ID,
      displayName: `${fixture.displayName} (default)`,
    }];
    for (const tenant of tenantFixtures) {
      const outcome = await upsertSeed(
        tenants,
        { realmId: fixture.realmId, tenantId: tenant.tenantId },
        {
          name: tenant.name,
          displayName: tenant.displayName,
          ...(tenant.parentTenantId ? { parentTenantId: tenant.parentTenantId } : {}),
          status: 'active',
        },
        { realmId: fixture.realmId, tenantId: tenant.tenantId },
        'Tenant',
      );
      console.log(`  tenant:   ${fixture.name}/${tenant.name} ${outcome.action}`);
    }

    for (const provider of fixture.providers ?? []) {
      const outcome = await upsertSeed(
        providers,
        { providerId: provider.providerId },
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
        { providerId: provider.providerId, realmId: fixture.realmId, tenantId: DEFAULT_TENANT_ID },
        'IdentityProvider',
      );
      console.log(`  provider: ${fixture.name}/${provider.name} (${provider.protocol}) ${outcome.action}`);
    }
  }
}
