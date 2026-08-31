import { readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import { v5 as uuidv5 } from 'uuid';

/**
 * Generates GIAM's fixtures from the platform's, ONCE.
 *
 * The platform's files are the source of the demo population; after this runs, GIAM's are
 * authoritative and the platform's stop being read. Two reasons this is a generator rather than a
 * seeder reading across:
 *
 * - GIAM must not carry the platform's vocabulary. Its seeders scan clean of any `party*` or
 *   `*InstanceReference` name, and a seeder reading a fixture full of them would smuggle the
 *   vocabulary in through the data instead of the code.
 * - The two products have to be separable. A seeder reaching into another application's fixture
 *   directory is a build-time dependency on that application existing.
 *
 * What is preserved exactly, because losing it is not recoverable:
 * subjects (already written into audit rows and application records) and credential hashes (the demo
 * passwords keep working because the hash is the same one).
 */

const PSP_DATA = resolve(__dirname, '../../../psp/backend/data');
const GIAM_DATA = resolve(__dirname, '../data');
const CREDENTIAL_NAMESPACE = '6f0d1b5e-3a2c-4c1e-9a7d-2b8f5c4e1a90';

interface LoginSource {
  customerAuthenticationInstanceReference: string;
  partyInstanceReference: string;
  customerAuthenticationEmailAddress?: string;
  customerAuthenticationCredentialHash?: string;
  customerAuthenticationUserRole: string;
  customerAuthenticationUserName?: string;
  customerAuthenticationAccountStatus?: string;
  customerAuthenticationDemoFeatured?: boolean;
}

interface PartySource {
  partyInstanceReference: string;
  partyType: string;
  partyName?: string;
  partyEmailAddress?: string;
  partyMobilePhoneNumber?: string;
}

interface CredentialSource {
  customerAuthenticationInstanceReference?: string;
  credentialId?: string;
  publicKeyPem?: string;
  alg?: string;
  signCount?: number;
  status?: string;
  authenticatorMetadata?: { label?: string };
}

function read<T>(name: string): T {
  return JSON.parse(readFileSync(resolve(PSP_DATA, name), 'utf8')) as T;
}

function splitName(formatted?: string) {
  if (!formatted) return undefined;
  const parts = formatted.trim().split(/\s+/);
  return {
    formatted,
    givenName: parts[0],
    ...(parts.length > 1 ? { familyName: parts.slice(1).join(' ') } : {}),
  };
}

function main(): void {
  const logins = read<LoginSource[]>('customerAuthentications.json');
  const parties = read<PartySource[]>('parties.json');
  const enrolled = read<CredentialSource[]>('enrolledCredentials.json');
  const byRef = new Map(parties.map((party) => [party.partyInstanceReference, party]));

  const identities = logins.map((login) => {
    const party = byRef.get(login.partyInstanceReference);
    const active = (login.customerAuthenticationAccountStatus ?? 'active') === 'active';
    const email = (login.customerAuthenticationEmailAddress ?? party?.partyEmailAddress ?? '').toLowerCase();
    return {
      // Which realm this population belongs to, as DATA. The seeder then resolves it by name and
      // carries no consumer identifier of its own.
      realm: 'leafypay',
      // Reused verbatim: this string is already in audit rows and in application records.
      subjectId: login.customerAuthenticationInstanceReference,
      userName: login.customerAuthenticationUserName ?? party?.partyName ?? email,
      kind: 'human' as const,
      ...(email ? { email } : {}),
      ...(party?.partyMobilePhoneNumber ? { phone: party.partyMobilePhoneNumber } : {}),
      ...(splitName(party?.partyName ?? login.customerAuthenticationUserName)
        ? { name: splitName(party?.partyName ?? login.customerAuthenticationUserName) }
        : {}),
      active,
      lifecycleState: active ? ('active' as const) : ('suspended' as const),
      demoFeatured: Boolean(login.customerAuthenticationDemoFeatured),
      // Carried so the authorization phase can assign the same roles to the same people without
      // reading the platform's fixtures again.
      roleName: login.customerAuthenticationUserRole,
    };
  });

  const credentials: Array<Record<string, unknown>> = [];
  for (const login of logins) {
    if (!login.customerAuthenticationCredentialHash) continue;
    const subjectId = login.customerAuthenticationInstanceReference;
    credentials.push({
      // Derived, so a reseed produces the same credential rather than a second one beside it.
      credentialId: uuidv5(`password:${subjectId}`, CREDENTIAL_NAMESPACE),
      subjectId,
      type: 'password',
      // Verbatim. The demo passwords keep working because this is the same hash and the same
      // algorithm verifies it.
      secretHash: login.customerAuthenticationCredentialHash,
      status: 'active',
      assurance: { level: 'aal1', method: 'password' },
    });
  }

  for (const record of enrolled) {
    const subjectId = record.customerAuthenticationInstanceReference;
    if (!subjectId || !record.publicKeyPem) continue;
    const label = record.authenticatorMetadata?.label ?? 'device';
    credentials.push({
      // The registration's own identifier is kept where it has one. It is what the device already
      // holds, and a device cannot be told that its credential was renamed.
      credentialId: record.credentialId ?? uuidv5(`public_key:${subjectId}:${label}`, CREDENTIAL_NAMESPACE),
      subjectId,
      type: 'public_key',
      publicKeyPem: record.publicKeyPem,
      algorithm: record.alg ?? 'ES256',
      signCount: record.signCount ?? 0,
      label,
      status: record.status ?? 'active',
      assurance: { level: 'aal2', method: 'public_key' },
    });
  }

  writeFileSync(resolve(GIAM_DATA, 'identities.json'), `${JSON.stringify(identities, null, 2)}\n`, 'utf8');
  writeFileSync(resolve(GIAM_DATA, 'credentials.json'), `${JSON.stringify(credentials, null, 2)}\n`, 'utf8');

  const byRole = identities.reduce<Record<string, number>>((counts, identity) => {
    counts[identity.roleName] = (counts[identity.roleName] ?? 0) + 1;
    return counts;
  }, {});
  console.log(`identities.json: ${identities.length}`);
  console.log(`credentials.json: ${credentials.length}`);
  console.log(`roles: ${JSON.stringify(byRole)}`);
}

main();
