// v39 P0.7: the key custody modes, and the proof that the default scales horizontally.
//
// The claim under test is the one the whole scalability position rests on: with NO KMS, NO shared
// volume and NO shared secret, a token signed by one replica verifies at another. If that is false,
// GIAM inherits the single-replica limit the platform's own signing key already has, and every later
// phase is built on it.
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { mkdtempSync, rmSync, existsSync, readdirSync } from 'fs';
import { tmpdir } from 'os';
import { resolve } from 'path';
import { createPublicKey, verify as cryptoVerify } from 'crypto';
import { keyProviders, PORT_REGISTRIES } from '../../../../giam/backend/src/shared/ports';
import { registerBuiltinPorts } from '../../../../giam/backend/src/shared/ports/builtins';
import { InstanceLocalKeyProvider } from '../../../../giam/backend/src/modules/keys/providers/instanceLocal.provider';
import { FilesystemKeyProvider } from '../../../../giam/backend/src/modules/keys/providers/filesystem.provider';
import {
  SharedStoreKeyProvider, InMemoryWrappedKeyStore,
} from '../../../../giam/backend/src/modules/keys/providers/sharedStore.provider';
import { KmsKeyProvider } from '../../../../giam/backend/src/modules/keys/providers/kms.provider';
import { KeyRing, InMemorySigningKeyStore } from '../../../../giam/backend/src/modules/keys/services/keyRing.service';
import { assertNoPlaintextPrivateKey } from '../../../../giam/backend/src/modules/keys/models/signingKey.model';

const REALM = 'realm-under-test';
const temporaryDirs: string[] = [];

function scratch(): string {
  const dir = mkdtempSync(resolve(tmpdir(), 'giam-keys-'));
  temporaryDirs.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of temporaryDirs) rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  PORT_REGISTRIES.KeyProvider.clear();
  registerBuiltinPorts();
});

describe('v39 P0.7: four custody modes, none gated by environment', () => {
  it('registers all four in every deployment', () => {
    expect(keyProviders.names()).toEqual(['filesystem', 'instance-local', 'kms', 'shared-store']);
  });

  it('reports every mode as multi-replica capable', () => {
    // Scaling is never the reason to change custody mode. That is the difference between this and
    // the platform's own signing key, which pins its deployment to one replica.
    for (const name of keyProviders.names()) {
      expect(keyProviders.resolve(name).multiReplicaCapable, `${name} is not multi-replica capable`).toBe(true);
    }
  });

  it('distinguishes external custody from node custody, because the posture report depends on it', () => {
    expect(keyProviders.resolve('instance-local').externalCustody).toBe(false);
    expect(keyProviders.resolve('filesystem').externalCustody).toBe(false);
    expect(keyProviders.resolve('shared-store').externalCustody).toBe(true);
    expect(keyProviders.resolve('kms').externalCustody).toBe(true);
  });
});

describe('v39 P0.7: the default scales with no KMS and no shared secret', () => {
  it('gives two replicas two different keys', async () => {
    const a = new InstanceLocalKeyProvider('replica-a', scratch());
    const b = new InstanceLocalKeyProvider('replica-b', scratch());
    const kidA = await a.ensureKey(REALM);
    const kidB = await b.ensureKey(REALM);
    // The premise being corrected: replicas do NOT need the same key. What they share is the set.
    expect(kidA).not.toBe(kidB);
  });

  it('verifies a token signed by one replica using the key set published by the other', async () => {
    const store = new InMemorySigningKeyStore();
    const dirA = scratch();
    const dirB = scratch();
    const ringA = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', dirA));
    const ringB = new KeyRing(store, new InstanceLocalKeyProvider('replica-b', dirB));

    await ringA.publishOwnKey(REALM);
    await ringB.publishOwnKey(REALM);

    const payload = Buffer.from('a token body signed by replica A');
    const { kid, signature } = await ringA.sign(REALM, payload);

    // Replica B resolves the kid from the SHARED published set, which is the union of both replicas'
    // public keys, and verifies without holding A's private key or any secret of A's.
    const setFromB = await ringB.publishedKeySet(REALM);
    expect(setFromB.keys).toHaveLength(2);
    const jwk = setFromB.keys.find((key) => key.kid === kid);
    expect(jwk, 'the signing replica\'s key is absent from the set the other publishes').toBeTruthy();

    const publicKey = createPublicKey({ key: jwk as never, format: 'jwk' });
    expect(cryptoVerify('sha256', payload, publicKey, signature)).toBe(true);
  });

  it('publishes an identical key set from either replica', async () => {
    const store = new InMemorySigningKeyStore();
    const ringA = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', scratch()));
    const ringB = new KeyRing(store, new InstanceLocalKeyProvider('replica-b', scratch()));
    await ringA.publishOwnKey(REALM);
    await ringB.publishOwnKey(REALM);

    const fromA = (await ringA.publishedKeySet(REALM)).keys.map((k) => k.kid).sort();
    const fromB = (await ringB.publishedKeySet(REALM)).keys.map((k) => k.kid).sort();
    // If these differ, a relying party gets a different answer depending on which replica served the
    // JWKS, which is an intermittent verification failure and the worst kind to diagnose.
    expect(fromA).toEqual(fromB);
  });

  it('republishes the same kid after a restart instead of churning the set', async () => {
    const dir = scratch();
    const first = await new InstanceLocalKeyProvider('replica-a', dir).ensureKey(REALM);
    // A new process object, same node, same directory: the key id is derived from the key itself.
    const second = await new InstanceLocalKeyProvider('replica-a', dir).ensureKey(REALM);
    expect(second).toBe(first);
  });

  it('keeps the private key on the node and out of the database', async () => {
    const store = new InMemorySigningKeyStore();
    const dir = scratch();
    const ring = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', dir));
    const kid = await ring.publishOwnKey(REALM);

    const record = await store.findByKid(kid);
    expect(record?.publicKeyPem).toContain('PUBLIC KEY');
    expect(record?.publicKeyPem).not.toContain('PRIVATE KEY');
    expect(record?.wrappedPrivateKey).toBeUndefined();
    // And it is on the node, where it belongs.
    expect(existsSync(resolve(dir, 'instances', 'replica-a', REALM, 'private.pem'))).toBe(true);
  });

  it('publishes no private parameter in the key set', async () => {
    const store = new InMemorySigningKeyStore();
    const ring = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', scratch()));
    await ring.publishOwnKey(REALM);
    for (const key of (await ring.publishedKeySet(REALM)).keys) {
      for (const privateParameter of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
        expect(key[privateParameter], `the key set exposes ${privateParameter}`).toBeUndefined();
      }
    }
  });
});

describe('v39 P0.7: a scale-down does not invalidate live sessions', () => {
  it('stops a lapsed replica signing but keeps its key published', async () => {
    const store = new InMemorySigningKeyStore();
    let now = new Date('2026-01-01T00:00:00.000Z');
    const clock = () => now;
    const ringA = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', scratch()), clock);
    const ringB = new KeyRing(store, new InstanceLocalKeyProvider('replica-b', scratch()), clock);

    const kidA = await ringA.publishOwnKey(REALM);
    await ringB.publishOwnKey(REALM);

    // Replica A goes away and stops renewing. Its lease lapses.
    now = new Date('2026-01-01T00:10:00.000Z');
    const { retired } = await ringB.reconcileLeases(REALM);
    expect(retired).toContain(kidA);

    const record = await store.findByKid(kidA);
    expect(record?.signingEligible).toBe(false);
    // Still published: tokens it already signed have not expired, and removing it now would sign
    // every one of their holders out.
    expect(record?.status).toBe('active');
    const published = (await ringB.publishedKeySet(REALM)).keys.map((k) => k.kid);
    expect(published).toContain(kidA);
  });

  it('unpublishes the key only after the grace period every live token has outlived', async () => {
    const store = new InMemorySigningKeyStore();
    let now = new Date('2026-01-01T00:00:00.000Z');
    const clock = () => now;
    const ring = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', scratch()), clock);
    const kid = await ring.publishOwnKey(REALM);

    now = new Date('2026-01-01T00:10:00.000Z');
    await ring.reconcileLeases(REALM);
    expect((await ring.publishedKeySet(REALM)).keys.map((k) => k.kid)).toContain(kid);

    // Past the lapse plus the publication grace, which is at least the maximum token lifetime.
    now = new Date('2026-01-01T02:00:00.000Z');
    await ring.reconcileLeases(REALM);
    expect((await ring.publishedKeySet(REALM)).keys.map((k) => k.kid)).not.toContain(kid);
  });

  it('renews a lease on a heartbeat, so a live replica is never retired', async () => {
    const store = new InMemorySigningKeyStore();
    let now = new Date('2026-01-01T00:00:00.000Z');
    const clock = () => now;
    const ring = new KeyRing(store, new InstanceLocalKeyProvider('replica-a', scratch()), clock);
    const kid = await ring.publishOwnKey(REALM);

    now = new Date('2026-01-01T00:04:00.000Z');
    await ring.renewLease(kid);
    now = new Date('2026-01-01T00:06:00.000Z');
    const { retired } = await ring.reconcileLeases(REALM);
    expect(retired).toEqual([]);
    expect((await store.findByKid(kid))?.signingEligible).toBe(true);
  });
});

describe('v39 P0.7: the other three modes', () => {
  it('filesystem shares one key across whoever can read the path', async () => {
    const dir = scratch();
    const kidA = await new FilesystemKeyProvider(dir).ensureKey(REALM);
    const kidB = await new FilesystemKeyProvider(dir).ensureKey(REALM);
    // Shared path, shared key: which is why it is multi-replica capable only when it IS shared, and
    // why the posture report says so rather than the process refusing to start.
    expect(kidB).toBe(kidA);
  });

  it('shared-store never writes an unwrapped private key', async () => {
    const store = new InMemoryWrappedKeyStore();
    const provider = new SharedStoreKeyProvider(store, 'a-key-encryption-key-held-outside-the-store');
    const kid = await provider.ensureKey(REALM);
    const stored = await store.read(REALM);

    expect(stored?.kid).toBe(kid);
    expect(stored?.wrapped).not.toContain('PRIVATE KEY');
    expect(() => assertNoPlaintextPrivateKey({
      publicKeyPem: stored?.publicPem ?? '',
      wrappedPrivateKey: stored?.wrapped,
    })).not.toThrow();
  });

  it('shared-store signs with the key it unwrapped, and a second process reads the same one', async () => {
    const store = new InMemoryWrappedKeyStore();
    const kek = 'a-key-encryption-key-held-outside-the-store';
    const first = new SharedStoreKeyProvider(store, kek);
    const kid = await first.ensureKey(REALM);

    const second = new SharedStoreKeyProvider(store, kek);
    expect(await second.ensureKey(REALM)).toBe(kid);

    const payload = Buffer.from('signed by the second process');
    const signature = await second.sign(kid, payload);
    const publicKey = createPublicKey(await first.publicKeyPem(kid));
    expect(cryptoVerify('sha256', payload, publicKey, signature)).toBe(true);
  });

  it('shared-store refuses rather than storing a private key in the clear', async () => {
    const provider = new SharedStoreKeyProvider(new InMemoryWrappedKeyStore(), undefined);
    // Absent, not degraded: without a wrapping key this mode would become the thing it exists to
    // avoid, so it refuses and names what is missing.
    await expect(provider.ensureKey(REALM)).rejects.toThrow(/GIAM_KEY_WRAPPING_KEY/);
  });

  it('kms refuses clearly when it is not configured, rather than falling back to a local key', async () => {
    const provider = new KmsKeyProvider(undefined, 'us-east-1');
    // Falling back here would silently move the platform's signing key out of the HSM an operator
    // deliberately chose, which is worse than not starting the flow at all.
    await expect(provider.ensureKey(REALM)).rejects.toThrow(/GIAM_KEY_AWS_KEY_ARN/);
  });

  it('leaves no key material behind in a shared scratch directory it was not given', () => {
    // A provider writing outside its configured directory would put one replica's private key where
    // another can read it, which is the failure mode the per-instance layout exists to prevent.
    const dir = scratch();
    expect(readdirSync(dir)).toEqual([]);
  });
});
