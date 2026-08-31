import { generateKeyPairSync, createPrivateKey, createPublicKey, KeyObject, sign as cryptoSign } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import type { KeyProvider } from '../../../shared/ports';
import { thumbprintKid } from '../services/jwk';
import { config } from '../../../config';

/**
 * One key pair at a configured path, shared by whoever can read that path.
 *
 * It exists for migration: it is the layout the platform's own signing key already uses, so a
 * deployment can move to GIAM without regenerating anything. It is multi-replica capable only when
 * the path is genuinely shared, and that is the one configuration on this platform that is
 * meaningfully weaker than the default.
 *
 * It still boots. A weaker choice warns, is reported as degraded on the posture endpoint, shows a
 * banner in the console and appears in the runbook's limitations. It does not refuse to start,
 * because refusing would make the operator's deployment decision the code's decision to make.
 */
export class FilesystemKeyProvider implements KeyProvider {
  readonly name = 'filesystem';

  // True only if the path is shared, which this process cannot know. Reported honestly through the
  // posture endpoint, where the replica count is also known.
  readonly multiReplicaCapable = true;

  readonly externalCustody = false;

  private readonly keys = new Map<string, { kid: string; privateKey: KeyObject; publicPem: string }>();

  constructor(private readonly storeDir: string = config.keys.storeDir) {}

  async ensureKey(realmId: string): Promise<string> {
    const cached = this.keys.get(realmId);
    if (cached) return cached.kid;

    const dir = resolve(this.storeDir, 'realms', realmId);
    const privatePath = resolve(dir, 'private.pem');

    let privatePem: string;
    if (existsSync(privatePath)) {
      privatePem = readFileSync(privatePath, 'utf8');
    } else {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
      privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
      mkdirSync(dir, { recursive: true });
      writeFileSync(privatePath, privatePem, { encoding: 'utf8', mode: 0o600 });
    }

    const privateKey = createPrivateKey(privatePem);
    const publicKey = createPublicKey(privateKey);
    const kid = thumbprintKid(publicKey);
    this.keys.set(realmId, {
      kid,
      privateKey,
      publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    });
    return kid;
  }

  private entryFor(kid: string) {
    const entry = [...this.keys.values()].find((candidate) => candidate.kid === kid);
    if (!entry) throw new Error(`No private key at the configured path for kid "${kid}"`);
    return entry;
  }

  async sign(kid: string, payload: Buffer): Promise<Buffer> {
    return cryptoSign('sha256', payload, this.entryFor(kid).privateKey);
  }

  async publicKeyPem(kid: string): Promise<string> {
    return this.entryFor(kid).publicPem;
  }
}
