import { Db } from 'mongodb';
import { IDENTITY_COLLECTION, CREDENTIAL_COLLECTION, REALM_COLLECTION } from '../../shared/models/collections';
import { IdentityRecord } from '../../modules/directory/models/identity.model';
import { CredentialRecord } from '../../modules/directory/models/credential.model';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { blindDigest } from '../encryption/digest';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';

/**
 * The demo population: every principal that can sign in, and the credential it signs in with.
 *
 * The fixtures are GIAM's own, generated once from the platform's and authoritative afterwards.
 * Nothing here reads another application's data directory, and nothing here carries another
 * product's vocabulary.
 *
 * Two things are preserved exactly, because losing either is not recoverable by a reseed:
 *
 * - **Subjects**, because they are already written into audit rows, sessions and application
 *   records. Regenerating them would break no test and would quietly orphan everything naming one.
 * - **Credential hashes**, because that is what makes the demo passwords keep working. The parity
 *   gate exists to prove nobody had to choose new ones.
 */

interface IdentityFixture {
  /** Which realm this principal belongs to, by name. Resolved here, so no id is hardcoded. */
  realm: string;
  subjectId: string;
  userName: string;
  kind: IdentityRecord['kind'];
  email?: string;
  phone?: string;
  name?: { formatted?: string; givenName?: string; familyName?: string };
  active: boolean;
  lifecycleState: IdentityRecord['lifecycleState'];
  demoFeatured?: boolean;
  roleName?: string;
  /** Binds an account holder to their own records, for a self-scoped role. */
  accountHolderRef?: string;
  owner?: { kind: string; ref: string; displayName?: string };
  workload?: IdentityRecord['workload'];
}

interface CredentialFixture {
  credentialId: string;
  subjectId: string;
  type: CredentialRecord['type'];
  secretHash?: string;
  publicKeyPem?: string;
  algorithm?: CredentialRecord['algorithm'];
  signCount?: number;
  label?: string;
  status: CredentialRecord['status'];
  assurance: CredentialRecord['assurance'];
}

export async function seedIdentities(db: Db, fixtureName = 'identities.json', credentialFixtureName = 'credentials.json'): Promise<void> {
  const fixtures = readSeedFile<IdentityFixture[]>(fixtureName);
  const credentialFixtures = readSeedFile<CredentialFixture[]>(credentialFixtureName);

  const identities = db.collection<IdentityRecord>(IDENTITY_COLLECTION);
  const credentials = db.collection<CredentialRecord>(CREDENTIAL_COLLECTION);
  const now = new Date().toISOString();

  // Realms resolved by name, once. A principal naming a realm that does not exist is a fixture error
  // worth failing on rather than a record written into a partition nothing can query.
  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray() as unknown as Array<{ realmId: string; name: string }>;
  const realmIdByName = new Map(realms.map((realm) => [realm.name, realm.realmId]));
  const realmIdBySubject = new Map<string, string>();

  const byKind: Record<string, number> = {};
  for (const fixture of fixtures) {
    const realmId = realmIdByName.get(fixture.realm);
    if (!realmId) throw new Error(`identities.json names realm "${fixture.realm}", which is not seeded`);
    realmIdBySubject.set(fixture.subjectId, realmId);
    byKind[fixture.kind] = (byKind[fixture.kind] ?? 0) + 1;
    await upsertSeed<IdentityRecord>(
      identities,
      { subjectId: fixture.subjectId },
      {
        userName: fixture.userName,
        kind: fixture.kind,
        ...(fixture.email ? { primaryEmail: fixture.email } : {}),
        // The digest carries the unique index that encrypted material cannot, and reveals nothing
        // without the key.
        ...(fixture.phone ? { primaryPhone: fixture.phone, primaryPhoneDigest: blindDigest(fixture.phone) } : {}),
        ...(fixture.name ? { name: fixture.name } : {}),
        ...(fixture.owner ? { owner: fixture.owner } : {}),
        ...(fixture.workload ? { workload: fixture.workload } : {}),
        active: fixture.active,
        lifecycleState: fixture.lifecycleState,
        sessionEpoch: 0,
        demoFeatured: Boolean(fixture.demoFeatured),
        ...(fixture.accountHolderRef ? { accountHolderRef: fixture.accountHolderRef } : {}),
      },
      { subjectId: fixture.subjectId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Identity',
    );
  }

  const byType: Record<string, number> = {};
  for (const fixture of credentialFixtures) {
    const realmId = realmIdBySubject.get(fixture.subjectId);
    // A credential for a principal that is not seeded would be unreachable and invisible, which is
    // worse than absent: it would look like a factor the subject holds and could never be used.
    if (!realmId) throw new Error(`credentials.json names a subject with no identity: ${fixture.subjectId}`);
    byType[fixture.type] = (byType[fixture.type] ?? 0) + 1;
    await upsertSeed<CredentialRecord>(
      credentials,
      { credentialId: fixture.credentialId },
      {
        subjectId: fixture.subjectId,
        type: fixture.type,
        ...(fixture.secretHash ? { secretHash: fixture.secretHash } : {}),
        ...(fixture.publicKeyPem ? { publicKeyPem: fixture.publicKeyPem } : {}),
        ...(fixture.algorithm ? { algorithm: fixture.algorithm } : {}),
        ...(fixture.signCount !== undefined ? { signCount: fixture.signCount } : {}),
        ...(fixture.label ? { label: fixture.label } : {}),
        status: fixture.status,
        assurance: fixture.assurance,
        createdAt: now,
      },
      { credentialId: fixture.credentialId, subjectId: fixture.subjectId, realmId, tenantId: DEFAULT_TENANT_ID },
      'Credential',
    );
  }

  const kinds = Object.entries(byKind).map(([kind, count]) => `${count} ${kind}`).join(', ');
  const types = Object.entries(byType).map(([type, count]) => `${count} ${type}`).join(', ');
  console.log(`  identity: ${fixtures.length} principal(s) (${kinds})`);
  console.log(`  credential: ${credentialFixtures.length} (${types})`);
}
