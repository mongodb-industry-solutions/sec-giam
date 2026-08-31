import type { KeyProvider } from '../../../shared/ports';
import { thumbprintKid } from '../services/jwk';
import { config } from '../../../config';
import { createPublicKey } from 'crypto';

/**
 * The best posture available: the private key never leaves the KMS or the HSM.
 *
 * GIAM asks the KMS to sign and never sees key material at all, so there is nothing on a node to
 * steal and nothing in the database to wrap. Rotation and revocation are the KMS's, which is the
 * point of using one rather than reimplementing it.
 *
 * Use it when a KMS is available. When one is not, the default provider is correct rather than
 * degraded: it scales horizontally with no KMS at all, so the absence of one is not a reason to
 * refuse to run.
 */

// The SDK is optional at runtime: a deployment that does not use this provider should not have to
// install it. Loaded lazily so its absence is a refusal from THIS provider, not a boot failure for
// everyone.
interface KmsClientLike {
  send(command: unknown): Promise<{ Signature?: Uint8Array; PublicKey?: Uint8Array }>;
}

export class KmsKeyProvider implements KeyProvider {
  readonly name = 'kms';

  readonly multiReplicaCapable = true;

  readonly externalCustody = true;

  private client: KmsClientLike | null = null;

  private commands: {
    SignCommand: new (input: unknown) => unknown;
    GetPublicKeyCommand: new (input: unknown) => unknown;
  } | null = null;

  private readonly byKid = new Map<string, { keyArn: string; publicPem: string }>();

  constructor(
    private readonly keyArn: string | undefined = config.keys.awsKeyArn,
    private readonly region: string = config.keys.awsRegion,
  ) {}

  private async sdk() {
    if (this.client && this.commands) return { client: this.client, commands: this.commands };
    if (!this.keyArn) {
      throw new Error('GIAM_KEY_AWS_KEY_ARN is required by the kms key provider.');
    }
    let module: Record<string, unknown>;
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires, global-require
      module = require('@aws-sdk/client-kms') as Record<string, unknown>;
    } catch {
      // Absent, not faked. Falling back to a local key here would silently move the platform's
      // signing key out of the HSM an operator deliberately chose.
      throw new Error(
        'The kms key provider needs @aws-sdk/client-kms, which is not installed. Install it, or '
        + 'configure GIAM_KEY_PROVIDER=instance-local, which is multi-replica correct without a KMS.',
      );
    }
    const KMSClient = module.KMSClient as new (input: unknown) => KmsClientLike;
    this.client = new KMSClient({ region: this.region });
    this.commands = {
      SignCommand: module.SignCommand as new (input: unknown) => unknown,
      GetPublicKeyCommand: module.GetPublicKeyCommand as new (input: unknown) => unknown,
    };
    return { client: this.client, commands: this.commands };
  }

  async ensureKey(_realmId: string): Promise<string> {
    const { client, commands } = await this.sdk();
    const response = await client.send(new commands.GetPublicKeyCommand({ KeyId: this.keyArn }));
    if (!response.PublicKey) throw new Error(`The KMS returned no public key for ${this.keyArn}`);
    const der = Buffer.from(response.PublicKey);
    const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' });
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const kid = thumbprintKid(publicKey);
    this.byKid.set(kid, { keyArn: this.keyArn as string, publicPem });
    return kid;
  }

  private entryFor(kid: string) {
    const entry = this.byKid.get(kid);
    if (!entry) throw new Error(`No KMS key registered for kid "${kid}"`);
    return entry;
  }

  async sign(kid: string, payload: Buffer): Promise<Buffer> {
    const { client, commands } = await this.sdk();
    const response = await client.send(new commands.SignCommand({
      KeyId: this.entryFor(kid).keyArn,
      Message: payload,
      MessageType: 'RAW',
      SigningAlgorithm: 'RSASSA_PKCS1_V1_5_SHA_256',
    }));
    if (!response.Signature) throw new Error('The KMS returned no signature');
    return Buffer.from(response.Signature);
  }

  async publicKeyPem(kid: string): Promise<string> {
    return this.entryFor(kid).publicPem;
  }
}
