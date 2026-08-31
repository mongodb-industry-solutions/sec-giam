// v39 P1.1: the registry holds every collection the data model names, and nothing it does not.
//
// Two failure directions, and both matter. A collection the model names and setup never creates is a
// feature that fails at its first write. A collection setup creates that the model does not name is a
// collection with no owning module, which is how a schema grows records nobody is accountable for.
import { describe, it, expect } from 'vitest';
import {
  GIAM_COLLECTIONS, GIAM_COLLECTIONS as REGISTRY, collectionSpec, encryptedCollections,
} from '../../../../giam/backend/src/shared/models/collections';
import { buildEncryptedFieldsMaps } from '../../../../giam/backend/src/vendors/encryption/encryptedFieldsMaps';

/** Every collection the data model specifies, by the section that specifies it. */
const SPECIFIED: Record<string, string[]> = {
  'realm and federation': ['realm', 'identityProvider', 'tenant'],
  directory: ['identity', 'credential', 'agent', 'tool', 'mcpServer'],
  oauth: ['client', 'apiKey', 'authorizationRequest', 'token', 'signingKey'],
  authorization: ['resourceServer', 'permission', 'role', 'roleAssignment', 'policy', 'relationship'],
  'session and consent': ['session', 'grant', 'delegation'],
  audit: ['securityEvent'],
  infrastructure: ['domainEvent', 'counters', 'idempotencyKey'],
};

/**
 * Collections the model explicitly DEFERS, with the phase that brings them.
 *
 * Listed so their absence is a recorded decision rather than an oversight, and so a reviewer looking
 * for one finds out where it went instead of assuming it was forgotten.
 */
const DEFERRED: Record<string, string> = {
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
      apiKeyHash: placeholder,
    })).sort();
    const marked = encryptedCollections().map((spec) => spec.name).sort();
    // A collection marked encrypted with no map would be created plain, and nothing at runtime would
    // complain: the field would simply be stored in the clear.
    expect(mapped).toEqual(marked);
  });

  it('marks nothing encrypted whose only sensitive value is already a one-way hash', () => {
    // Encrypting a bcrypt hash buys nothing and blocks the lookup that verifies it.
    for (const name of ['credential', 'client']) {
      expect(collectionSpec(name)?.encrypted, `${name} should not be encrypted`).toBeFalsy();
    }
  });

  it('keeps the registry free of duplicates', () => {
    const names = GIAM_COLLECTIONS.map((spec) => spec.name);
    expect(new Set(names).size).toBe(names.length);
  });
});
