import { generateKeyPairSync, createPrivateKey, createPublicKey, KeyObject, sign as cryptoSign } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import type { KeyProvider } from '../../../shared/ports';
import { thumbprintKid } from '../services/jwk';
import { config } from '../../../config';

/**
 * The default: one key pair per replica, one shared published key set.
 *
 * The mistaken premise this corrects is that every replica must sign with the same key. It does not.
 * What must be shared is the PUBLISHED KEY SET, not the private key. Each replica generates its own
 * pair with its own kid, registers only the public half, and the realm's JWKS is the union. A token
 * signed here verifies at any other replica and at every resource server, and there is no shared
 * secret, no shared volume and no KMS anywhere in that sentence.
 *
 * This is better isolation than one shared key, not a downgrade from it: compromising a node yields
 * one key, and revoking it means removing one entry from the set rather than rotating the signer for
 * the whole deployment.
 *
 * The private key is written to this node's own directory so a restart republishes the same kid
 * instead of churning the key set. It never touches the database and never leaves the node.
 */
export class InstanceLocalKeyProvider implements KeyProvider {
  readonly name = 'instance-local';

  readonly multiReplicaCapable = true;

  readonly externalCustody = false;

  private readonly keys = new Map<string, { kid: string; privateKey: KeyObject; publicPem: string }>();

  constructor(
    private readonly instanceId: string = config.keys.instanceId,
    private readonly storeDir: string = config.keys.storeDir,
  ) {}

  /** This replica's own directory. Two replicas sharing a volume still keep separate keys. */
  private directory(realmId: string): string {
    return resolve(this.storeDir, 'instances', this.instanceId, realmId);
  }

  async ensureKey(realmId: string): Promise<string> {
    const cached = this.keys.get(realmId);
    if (cached) return cached.kid;

    const dir = this.directory(realmId);
    const privatePath = resolve(dir, 'private.pem');

    let privatePem: string;
    if (existsSync(privatePath)) {
      privatePem = readFileSync(privatePath, 'utf8');
    } else {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      mkdirSync(dir, { recursive: true });
      // Owner-only: a signing key readable by anything else on the node is not a private key.
      writeFileSync(privatePath, privatePem, { encoding: 'utf8', mode: 0o600 });
    }

    const privateKey = createPrivateKey(privatePem);
    const publicKey = createPublicKey(privateKey);
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const kid = thumbprintKid(publicKey);

    this.keys.set(realmId, { kid, privateKey, publicPem });
    return kid;
  }

  private entryFor(kid: string): { kid: string; privateKey: KeyObject; publicPem: string } {
    const entry = [...this.keys.values()].find((candidate) => candidate.kid === kid);
    // A kid this replica does not hold is not an error to paper over: another replica signed it, and
    // this replica can verify it from the published set but cannot sign with it.
    if (!entry) throw new Error(`This instance holds no private key for kid "${kid}"`);
    return entry;
  }

  async sign(kid: string, payload: Buffer): Promise<Buffer> {
    return cryptoSign('sha256', payload, this.entryFor(kid).privateKey);
  }

  async publicKeyPem(kid: string): Promise<string> {
    return this.entryFor(kid).publicPem;
  }
}
