import { Db } from 'mongodb';
import { v5 as uuidv5 } from 'uuid';
import { POLICY_COLLECTION, REALM_COLLECTION } from '../../shared/models/collections';
import { PolicyRecord, PolicyCondition } from '../../modules/authorization/models/policy.model';
import { validatePolicy } from '../../modules/authorization/services/policyAdmin.service';
import { DEFAULT_TENANT_ID } from '../../shared/models/base.model';
import { upsertSeed } from './upsertSeed';
import { readSeedFile } from './readSeedFile';

/**
 * The example policies, chosen to demonstrate the mechanism rather than to flatter it.
 *
 * Three of them, and each earns its place. One allows, so the screen has something that grants. One
 * DENIES what the first allows, because deny-wins is the rule the whole model rests on and a rule
 * nobody can see fire is a rule nobody has checked. One carries a condition, so the closed identity
 * vocabulary is visible as data instead of only as a form control.
 *
 * Each is one policy stating one effect, per ADR section 7. The pair that disagree are two separate
 * records rather than two statements in one, which is what makes deny-wins a rule ACROSS policies
 * instead of an ordering question inside one.
 *
 * A fresh database with none of these would ship a blank screen, and a blank screen is the state in
 * which a policy surface looks finished and proves nothing.
 */

const POLICY_NAMESPACE = 'c7d2f8a1-3e5b-4c9d-8a6f-1b4e2d7c9a30';

interface PolicyFixture {
  realm: string;
  name: string;
  version: number;
  status: PolicyRecord['status'];
  effect: 'allow' | 'deny';
  permissions: string[];
  resource: { names?: string[]; pattern?: string };
  principals?: string[];
  conditions?: PolicyCondition[];
  obligations?: PolicyRecord['obligations'];
  approvedBy?: string;
  effectiveFrom?: string;
  reason?: string;
}

function policyId(realmId: string, name: string): string {
  return uuidv5(`policy:${realmId}:${name}`, POLICY_NAMESPACE);
}

export async function seedPolicies(db: Db, fixtureName = 'policies.json'): Promise<void> {
  const fixtures = readSeedFile<PolicyFixture[]>(fixtureName);

  const realms = await db.collection(REALM_COLLECTION)
    .find({}, { projection: { _id: 0, realmId: 1, name: 1 } })
    .toArray() as unknown as Array<{ realmId: string; name: string }>;
  const realmIdByName = new Map(realms.map((realm) => [realm.name, realm.realmId]));

  const policies = db.collection<PolicyRecord>(POLICY_COLLECTION);
  let seeded = 0;

  for (const fixture of fixtures) {
    const realmId = realmIdByName.get(fixture.realm);
    if (!realmId) throw new Error(`${fixtureName} names realm "${fixture.realm}", which is not seeded`);

    // The same check the API applies, against the same function. A fixture is not exempt from the
    // condition vocabulary: seeding a condition the evaluator cannot read would produce a policy
    // that exists, appears to decide something, and silently never applies.
    const invalid = validatePolicy(fixture);
    if (invalid) throw new Error(`${fixtureName} policy "${fixture.name}": ${invalid.title}. ${invalid.detail}`);

    const id = policyId(realmId, fixture.name);
    await upsertSeed<PolicyRecord>(
      policies,
      { policyId: id },
      {
        name: fixture.name,
        version: fixture.version,
        status: fixture.status,
        effect: fixture.effect,
        permissions: fixture.permissions,
        resource: fixture.resource,
        conditions: fixture.conditions ?? [],
        ...(fixture.principals?.length ? { principals: fixture.principals } : {}),
        ...(fixture.obligations?.length ? { obligations: fixture.obligations } : {}),
        ...(fixture.approvedBy ? { approvedBy: fixture.approvedBy } : {}),
        ...(fixture.effectiveFrom ? { effectiveFrom: fixture.effectiveFrom } : {}),
        ...(fixture.reason ? { reason: fixture.reason } : {}),
      },
      { policyId: id, realmId, tenantId: DEFAULT_TENANT_ID },
      'Policy',
    );
    seeded += 1;
  }

  console.log(`  policy: ${seeded}`);
}
