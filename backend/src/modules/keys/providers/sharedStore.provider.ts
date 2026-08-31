import {
  generateKeyPairSync, createPrivateKey, createPublicKey, createCipheriv, createDecipheriv,
  randomBytes, scryptSync, sign as cryptoSign, KeyObject,
} from 'crypto';
import type { KeyProvider } from '../../../shared/ports';
import { thumbprintKid } from '../services/jwk';
import { config } from '../../../config';

/**
 * Where a wrapped private key is kept. The database is the obvious implementation, and an in-memory
 * one exists so the seam can be exercised without one.
 */
export interface WrappedKeyStore {
  read(realmId: string): Promise<{ kid: string; wrapped: string; publicPem: string } | null>;
  write(realmId: string, entry: { kid: string; wrapped: string; publicPem: string }): Promise<void>;
}

export class InMemoryWrappedKeyStore implements WrappedKeyStore {
  private readonly entries = new Map<string, { kid: string; wrapped: string; publicPem: string }>();

  async read(realmId: string) {
    return this.entries.get(realmId) ?? null;
  }

  async write(realmId: string, entry: { kid: string; wrapped: string; publicPem: string }) {
    this.entries.set(realmId, entry);
  }
}

/**
 * One signing identity for the whole deployment, held envelope-encrypted.
 *
 * The private key is stored WRAPPED under a key-encryption key that lives outside the store, so a
 * copy of the database discloses nothing: the wrapped key is useless without the wrapping key, and
 * the wrapping key is the thing that matters. That distinction is why this is a supported mode and a
 * plaintext PEM in the database is not.
 *
 * Use it when one signing identity for the whole deployment is genuinely required. Otherwise the
 * default is better, because it never assembles a single key whose loss compromises everything.
 */
export class SharedStoreKeyProvider implements KeyProvider {
  readonly name = 'shared-store';

  readonly multiReplicaCapable = true;

  readonly externalCustody = true;

  private readonly unwrapped = new Map<string, { kid: string; privateKey: KeyObject; publicPem: string }>();

  constructor(
    private readonly store: WrappedKeyStore = new InMemoryWrappedKeyStore(),
    private readonly wrappingKey: string | undefined = config.keys.wrappingKey,
  ) {}

  private cipherKey(salt: Buffer): Buffer {
    if (!this.wrappingKey) {
      // Absent, not faked: without a key-encryption key this mode would store a private key in the
      // clear, which is the exact thing it exists to avoid.
      throw new Error(
        'GIAM_KEY_WRAPPING_KEY is required by the shared-store key provider. Without it the private '
        + 'key would be stored unwrapped, which this mode exists to prevent.',
      );
    }
    return scryptSync(this.wrappingKey, salt, 32);
  }

  private wrap(privatePem: string): string {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.cipherKey(salt), iv);
    const sealed = Buffer.concat([cipher.update(privatePem, 'utf8'), cipher.final()]);
    return [salt, iv, cipher.getAuthTag(), sealed].map((part) => part.toString('base64')).join('.');
  }

  private unwrap(wrapped: string): string {
    const [salt, iv, tag, sealed] = wrapped.split('.').map((part) => Buffer.from(part, 'base64'));
    const decipher = createDecipheriv('aes-256-gcm', this.cipherKey(salt), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(sealed), decipher.final()]).toString('utf8');
  }

  async ensureKey(realmId: string): Promise<string> {
    const cached = this.unwrapped.get(realmId);
    if (cached) return cached.kid;

    const stored = await this.store.read(realmId);
    if (stored) {
      const privateKey = createPrivateKey(this.unwrap(stored.wrapped));
      this.unwrapped.set(realmId, { kid: stored.kid, privateKey, publicPem: stored.publicPem });
      return stored.kid;
    }

    const { privateKey: generated } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const privatePem = generated.export({ type: 'pkcs8', format: 'pem' }).toString();
    const privateKey = createPrivateKey(privatePem);
    const publicKey = createPublicKey(privateKey);
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const kid = thumbprintKid(publicKey);

    await this.store.write(realmId, { kid, wrapped: this.wrap(privatePem), publicPem });
    this.unwrapped.set(realmId, { kid, privateKey, publicPem });
    return kid;
  }

  private entryFor(kid: string) {
    const entry = [...this.unwrapped.values()].find((candidate) => candidate.kid === kid);
    if (!entry) throw new Error(`No wrapped private key loaded for kid "${kid}"`);
    return entry;
  }

  async sign(kid: string, payload: Buffer): Promise<Buffer> {
    return cryptoSign('sha256', payload, this.entryFor(kid).privateKey);
  }

  async publicKeyPem(kid: string): Promise<string> {
    return this.entryFor(kid).publicPem;
  }
}
