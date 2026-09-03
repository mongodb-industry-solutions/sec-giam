// v39 P1.1: the registry holds every collection the data model names, and nothing it does not.
//
// Two failure directions, and both matter. A collection the model names and setup never creates is a
// feature that fails at its first write. A collection setup creates that the model does not name is a
// collection with no owning module, which is how a schema grows records nobody is accountable for.
import { describe, it, expect } from 'vitest';
import {
  GIAM_COLLECTIONS, GIAM_COLLECTIONS as REGISTRY, collectionSpec, encryptedCollections,
} from '../../../backend/src/shared/models/collections';
import { buildEncryptedFieldsMaps } from '../../../backend/src/vendors/encryption/encryptedFieldsMaps';

/** Every collection the data model specifies, by the section that specifies it. */
const SPECIFIED: Record<string, string[]> = {
  'realm and its authentication paths': ['realm', 'domain'],
  directory: ['principal', 'credential'],
  oauth: ['state', 'key'],
  authorization: ['resource', 'role', 'policy'],
  'session and consent': ['session', 'grant'],
  audit: ['audit'],
  infrastructure: ['eventbus'],
};

/**
 * Collections the model explicitly DEFERS, with the phase that brings them.
 *
 * Listed so their absence is a recorded decision rather than an oversight, and so a reviewer looking
 * for one finds out where it went instead of assuming it was forgotten.
 */
const DEFERRED: Record<string, string> = {
  // v40 P0: removed outright, nothing read or wrote them. Listed so their absence is a decision.
  relationship: 'P0, removed: four indexes, no reader and no writer',
  counters: 'P0, removed: one index, no caller, identifiers are randomUUID',
  idempotencyKey: 'P0, removed: two indexes, no writer',
  tenant: 'P0, removed: tenantId survives as a field on every scoped collection',
  // v40: absorbed rather than removed. Each names the collection that now carries it, so a reader
  // looking for one finds where it went instead of assuming it was forgotten.
  agent: 'P2, absorbed: principal.agent sub document',
  roleAssignment: 'P2, absorbed: principal.roles[] with an optional expiry',
  client: 'P3, absorbed: credential of type oauth_client',
  apiKey: 'P3, absorbed: credential of type api_key',
  tool: 'P4, absorbed: resource of kind tool',
  mcpServer: 'P4, absorbed: resource of kind mcp_server',
  resourceServer: 'P4, absorbed: resource of kind api',
  permission: 'P5, absorbed: a permission is the string resource:action, not a row',
  token: 'P6, absorbed: nothing redeemable is stored, session carries the fact of access',
  delegation: 'P7, absorbed: a delegation is a grant with a purpose',
  group: 'P8+, SCIM Groups',
  provisioningTarget: 'P8+, outbound provisioning',
  provisioningJob: 'P8+, outbound provisioning',
  attestation: 'P8+, workload identity trust anchors',
  elevationRequest: 'P8+, the approval workflow around an elevation',
  effectiveEntitlement: 'P8+, an optional materialised projection',
  trustDomain: 'P10, SPIFFE trust domains',
};

describe('v39 P1.1: the collection registry matches the data model', () => {
  it('registers every collection the model specifies', () => {
    const registered = new Set(REGISTRY.map((spec) => spec.name));
    const missing = Object.values(SPECIFIED).flat().filter((name) => !registered.has(name));
    expect(missing, `specified but not registered: ${missing.join(', ')}`).toEqual([]);
  });

  it('registers nothing the model does not specify, and nothing it defers', () => {
    const specified = new Set(Object.values(SPECIFIED).flat());
    const unexpected = REGISTRY.map((spec) => spec.name).filter((name) => !specified.has(name));
    expect(unexpected, `registered but not specified: ${unexpected.join(', ')}`).toEqual([]);

    const deferredButPresent = Object.keys(DEFERRED).filter((name) => specified.has(name));
    expect(deferredButPresent, deferredButPresent.join(', ')).toEqual([]);
  });

  it('gives every collection an owning module and a stated purpose', () => {
    // The mechanical version of the ownership matrix: a collection with no owner is undocumented
    // ownership, and a reviewer noticing is not a control.
    for (const spec of REGISTRY) {
      expect(spec.module, `${spec.name} has no owning module`).toMatch(/^[a-z-]+$/);
      expect(spec.purpose.length, `${spec.name} has no purpose`).toBeGreaterThan(20);
    }
  });

  it('records a reason for every deferred collection', () => {
    for (const [name, reason] of Object.entries(DEFERRED)) {
      expect(reason, `${name} is deferred with no phase`).toMatch(/^P\d+/);
    }
  });

  it('declares an encrypted-fields map for exactly the collections marked encrypted', () => {
    const placeholder = null as never;
    const mapped = Object.keys(buildEncryptedFieldsMaps({
      identityEmail: placeholder,
      identityPhone: placeholder,
      identityName: placeholder,
    })).sort();
    const marked = encryptedCollections().map((spec) => spec.name).sort();
    // A collection marked encrypted with no map would be created plain, and nothing at runtime would
    // complain: the field would simply be stored in the clear. So every marked collection must be
    // mapped, and nothing else may be. P3.3 dropped the apiKey entry rather than carrying it onto
    // credential: it encrypted a one-way hash, and keeping it would have made credential an
    // encrypted collection on what is now one of the hottest lookups in the system.
    expect(mapped).toEqual(marked);
  });

  it('marks nothing encrypted whose only sensitive value is already a one-way hash', () => {
    // Encrypting a bcrypt hash buys nothing and blocks the lookup that verifies it. credential now
    // carries the client registrations too, so this is also what keeps the hottest lookup in the
    // system off an encrypted collection.
    for (const name of ['credential']) {
      expect(collectionSpec(name)?.encrypted, `${name} should not be encrypted`).toBeFalsy();
    }
  });

  it('registers exactly the thirteen collections the target model names', () => {
    // The number is the point of the refactor, so it is asserted rather than described. A
    // fourteenth is either a decision recorded in the ADR or a collection that crept back.
    expect(GIAM_COLLECTIONS).toHaveLength(13);
  });

  it('keeps the registry free of duplicates', () => {
    const names = GIAM_COLLECTIONS.map((spec) => spec.name);
    expect(new Set(names).size).toBe(names.length);
  });
});
