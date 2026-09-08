// v41 D35: a change to configuration is recorded with what it was before.
//
// The defect is quiet and that is what makes it worth a test. Administrative changes were recorded
// inconsistently and never with the previous value: `meta.version` moves, so a reviewer can see THAT
// something changed and never WHAT. "Who changed this policy from allow to deny" was unanswerable.
// PCI DSS 10.2.1.x requires every administrative action to be recorded and NIST SP 800-53 AU-3
// requires the content to be enough to reconstruct it, which a counter is not.
//
// This test does two things. It asserts the recorder behaves, and it enumerates every write path
// that does NOT yet use it. That second half is the point: the debt was invisible, and an
// enumeration with an argued exemption per entry makes it visible and stops it growing. A new
// service that writes to a scoped collection fails here until somebody decides which it is.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'fs';
import { resolve, join, relative } from 'path';
import { diffOf } from '../../../backend/src/modules/audit/services/configurationChange';

const SOURCE = resolve(__dirname, '../../../backend/src');

/**
 * Write paths that do not record a configuration change, each with the reason.
 *
 * Every entry is a decision, not an oversight, and shrinking this list is the remaining work of
 * D35. Adding to it should be uncomfortable, which is why a reason is required beside each.
 */
const NOT_YET_RECORDING: Record<string, string> = {
  // Records EVIDENCE rather than configuration. It is the sink these events are written to, so a
  // configuration change recorded about it would be circular.
  'modules/audit/services/securityEvent.service.ts': 'the trail itself',
  'modules/audit/services/configurationChange.ts': 'the recorder',

  // Not configuration. These write operational state whose whole lifecycle is already a recorded
  // event: a session is created and ended, a ticket is minted and consumed, and both emit their own.
  'modules/authentication/services/session.service.ts': 'session lifecycle, recorded as its own events',
  'modules/oauth/controllers/authorize.controller.ts': 'ticket lifecycle, recorded as authorization events',
  'modules/oauth/controllers/token.controller.ts': 'ticket redemption, recorded as issuance events',
  'modules/oauth/services/tokenIssuer.service.ts': 'session revocation, recorded as its own events',
  'modules/oauth/services/delegationExchange.service.ts': 'reads a grant to authorise a hop, recorded as an exchange event',
  'modules/authentication/services/backchannel.service.ts': 'ticket lifecycle, recorded as authentication events',
  'modules/authentication/services/enrollment.service.ts': 'credential enrolment, which emits a CAEP signal',

  // KNOWN DEBT. Each mutates configuration and records an event without the previous value, so a
  // reviewer can see that something changed and not what it was. This is the remaining work.
  'modules/authorization/services/roleAdmin.service.ts': 'DEBT: records the change, not the previous value',
  'modules/authorization/controllers/crossRealm.controller.ts': 'DEBT: grants administration ACROSS a realm boundary, recorded without the previous grant',
  'modules/realm/controllers/federation.controller.ts': 'DEBT: creates and changes authentication domains, not diffed',
  'modules/directory/controllers/scim.controller.ts': 'DEBT: inbound provisioning writes principals, not diffed',
  // PCI DSS 10.2.1.x names changes to identification and authentication credentials
  // specifically, so this one is the highest-value debt in the list.
  'modules/directory/services/credentialStores.ts': 'DEBT: credential material changes, not diffed',
  'modules/authorization/controllers/resource.controller.ts': 'DEBT: replaces an action catalog wholesale, unrecorded',
  'modules/realm/controllers/domain.controller.ts': 'DEBT: records the change, not the previous value',
  'modules/oauth/controllers/registration.controller.ts': 'DEBT: client registration changes, not diffed',
  'modules/directory/controllers/registration.controller.ts': 'DEBT: principal creation, not diffed',
  'modules/directory/services/directory.service.ts': 'DEBT: principal mutations, not diffed',
  'modules/directory/services/scim.service.ts': 'DEBT: inbound provisioning, not diffed',
  'modules/privilege/services/elevation.service.ts': 'DEBT: role holdings, recorded without the previous set',
  'modules/keys/services/keyRing.service.ts': 'DEBT: key custody changes, not diffed',
  'modules/keys/services/signingKeyStore.ts': 'DEBT: key material lifecycle, not diffed',
  'modules/provisioning/services/webhookTarget.ts': 'DEBT: receiver registration, not diffed',
  'modules/authorization/services/signals.service.ts': 'DEBT: receiver subscriptions, not diffed',
  'modules/consent/services/grant.service.ts': 'records before and after on a scope change; withdrawal records the scope',
  // The realm write is diffed by its caller (`realmAdmin.controller.ts`, `recordConfigurationChange`
  // on both create and update). DEBT: the local domain created alongside a new realm is a second,
  // separate write in this same method, and that one is not diffed by anybody yet.
  'modules/realm/services/realm.service.ts': 'realm write recorded by its caller; DEBT: the local domain created alongside it is not',
};

/** Every `.ts` under `backend/src`, excluding setup and seed, which build rather than change. */
function sourceFiles(): string[] {
  const found: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (entry.endsWith('.ts')) {
        found.push(full);
      }
    }
  };
  walk(SOURCE);
  return found.filter((file) => {
    const rel = relative(SOURCE, file).replace(/\\/g, '/');
    // Setup and the seeder BUILD the database rather than changing a running one, and every change
    // they make is reproducible from the fixtures by definition.
    return !rel.startsWith('vendors/setup/') && !rel.startsWith('vendors/seed/');
  });
}

/** Collections whose contents are configuration, so a change to one is an administrative act. */
const CONFIGURATION_COLLECTIONS = [
  'REALM_COLLECTION', 'DOMAIN_COLLECTION', 'PRINCIPAL_COLLECTION', 'CREDENTIAL_COLLECTION',
  'ROLE_COLLECTION', 'POLICY_COLLECTION', 'RESOURCE_COLLECTION', 'GRANT_COLLECTION',
  'SESSION_COLLECTION', 'TICKET_COLLECTION', 'KEY_COLLECTION',
];

const WRITES = /\.(updateOne|updateMany|replaceOne|insertOne|insertMany|deleteOne|deleteMany|findOneAndUpdate|bulkWrite)\(/;

describe('v41 D35: what changed, and what it was before', () => {
  it('names the fields that moved, with both values, and nothing else', () => {
    const diff = diffOf(
      { effect: 'allow', permissions: ['a'], reason: 'why', meta: { version: 1 } },
      { effect: 'deny', permissions: ['a'], reason: 'why', meta: { version: 2 } },
    );
    expect(diff.changed).toEqual(['effect']);
    expect(diff.before).toEqual({ effect: 'allow' });
    expect(diff.after).toEqual({ effect: 'deny' });
    // `meta` is excluded: a version counter moving on every write is noise, and it is the very
    // thing that was standing in for a diff.
    expect(diff.changed).not.toContain('meta');
  });

  it('reports an empty change rather than pretending nothing happened', () => {
    // A no-op is still a decision somebody made. A trail holding only the changes cannot tell
    // "reviewed and left alone" from "nobody looked".
    const diff = diffOf({ effect: 'deny' }, { effect: 'deny' });
    expect(diff.changed).toEqual([]);
  });

  it('treats an added or removed field as a change, so a deletion is not silent', () => {
    expect(diffOf({ reason: 'why' }, {}).changed).toEqual(['reason']);
    expect(diffOf({}, { reason: 'why' }).changed).toEqual(['reason']);
  });
});

describe('v41 D35: every write to configuration is accounted for', () => {
  /**
   * The coverage half, and the reason it is an enumeration rather than a pass or fail.
   *
   * A new service writing to a scoped collection without recording the change is invisible in a
   * diff and obvious here. It fails until somebody adds it to the list WITH A REASON, which is a
   * deliberate act a reviewer sees, or wires up the recorder, which is the outcome the list exists
   * to push towards.
   */
  it('either records the change or is listed as not doing so, with a reason', () => {
    const unaccounted: string[] = [];

    for (const file of sourceFiles()) {
      const text = readFileSync(file, 'utf8');
      const rel = relative(SOURCE, file).replace(/\\/g, '/');

      const touchesConfiguration = CONFIGURATION_COLLECTIONS.some((name) => text.includes(name));
      if (!touchesConfiguration || !WRITES.test(text)) continue;
      if (text.includes('recordConfigurationChange')) continue;
      if (NOT_YET_RECORDING[rel]) continue;

      unaccounted.push(rel);
    }

    expect(
      unaccounted,
      'these write to configuration, record no change, and are not listed as exempt: '
      + `${unaccounted.join(', ')}. Wire up recordConfigurationChange, or add an entry saying why not.`,
    ).toEqual([]);
  });

  it('keeps the exemption list honest, by requiring every entry to still exist', () => {
    // A stale entry is worse than none: it excuses a file that has moved or gone, and quietly
    // exempts whatever takes its place.
    const present = new Set(sourceFiles().map((file) => relative(SOURCE, file).replace(/\\/g, '/')));
    const stale = Object.keys(NOT_YET_RECORDING).filter((entry) => !present.has(entry));
    expect(stale, `listed but no longer present: ${stale.join(', ')}`).toEqual([]);
  });
});
