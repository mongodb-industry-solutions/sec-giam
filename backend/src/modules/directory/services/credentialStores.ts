import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import { createVerify, createPublicKey } from 'crypto';
import type { CredentialStore } from '../../../shared/ports';
import { CREDENTIAL_COLLECTION } from '../../../shared/models/collections';
import { CredentialRecord, isUsable } from '../models/credential.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';

/**
 * Where credential material lives and how it is verified.
 *
 * Two implementations from the start, because the port only proves itself as an abstraction when
 * something other than the obvious one goes through it. A password and a registered public key are
 * verified in genuinely different ways: one compares a salted hash, the other checks a signature over
 * a challenge and a counter. Nothing above this line needs to know which.
 *
 * The database handle is bound rather than passed, so the port stays free of any storage vocabulary
 * and a future store can hold its material somewhere else entirely.
 */

let boundDb: Db | null = null;

export function bindCredentialStores(db: Db): void {
  boundDb = db;
}

function collection(): Db['collection'] extends never ? never : ReturnType<Db['collection']> {
  if (!boundDb) throw new Error('Credential stores are not bound to a database');
  return boundDb.collection(CREDENTIAL_COLLECTION);
}

async function load(credentialId: string): Promise<CredentialRecord | null> {
  return collection().findOne({ credentialId }, { projection: { _id: 0 } }) as Promise<CredentialRecord | null>;
}

async function markUsed(credentialId: string, patch: Record<string, unknown> = {}): Promise<void> {
  // Bookkeeping only. A failure here must never turn a successful authentication into an error, so
  // callers do not await it.
  await collection().updateOne(
    { credentialId },
    { $set: { lastUsedAt: new Date().toISOString(), ...patch } },
  );
}

/**
 * Moves the anti-clone counter forward, and says whether it moved.
 *
 * The update is CONDITIONAL on the counter still holding the value this verification read. When it
 * does not, another proof over the same key advanced it in between, which means two holders produced
 * a valid signature from the same counter state: the shape of an authenticator that exists twice.
 * A blind increment cannot tell that apart from ordinary use, which is why it produced no signal.
 */
async function advanceSignCount(credentialId: string, from: number): Promise<boolean> {
  const result = await collection().updateOne(
    { credentialId, $or: [{ signCount: from }, { signCount: { $exists: false } }] },
    { $set: { lastUsedAt: new Date().toISOString(), signCount: from + 1 } },
  );
  return result.matchedCount > 0;
}

export const bcryptPasswordStore: CredentialStore = {
  name: 'bcrypt-password',
  credentialType: 'password',

  async verify(credentialId, presented) {
    const credential = await load(credentialId);
    if (!credential?.hash || !isUsable(credential)) return false;
    const ok = await bcrypt.compare(presented, credential.hash);
    if (ok) markUsed(credentialId).catch(() => {});
    return ok;
  },

  async issue(subjectId, secret) {
    // Cost 12, matching what the platform already uses, so migrated hashes and new ones are
    // indistinguishable in verification time as well as in shape.
    return { subjectId, hash: await bcrypt.hash(secret, 12) };
  },
};

/**
 * A registered public key, verified by signature over the challenge the server issued.
 *
 * The presented value is `<challenge>.<signature>`: the challenge is echoed so the verification is
 * over exactly the bytes the server chose, rather than over whatever the client decided to sign.
 */
export const publicKeyStore: CredentialStore = {
  name: 'public-key',
  credentialType: 'public_key',

  async verify(credentialId, presented) {
    const credential = await load(credentialId);
    if (!credential?.publicKeyPem || !isUsable(credential)) return false;

    const separator = presented.lastIndexOf('.');
    if (separator <= 0) return false;
    const challenge = presented.slice(0, separator);
    const signature = presented.slice(separator + 1);

    try {
      const key = createPublicKey(credential.publicKeyPem);
      const verifier = createVerify('sha256');
      verifier.update(challenge);
      verifier.end();
      const ok = verifier.verify(
        { key, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signature, 'base64url'),
      );
      if (ok) {
        // The anti-clone counter moves forward on every use, and a counter that did not move is a
        // credential-cloning indicator. Not awaited: bookkeeping must never turn a successful
        // authentication into an error, and the signal is recorded rather than raised at the caller,
        // which asked whether this proof holds and got a truthful answer.
        void advanceSignCount(credentialId, credential.signCount ?? 0)
          .then((advanced) => {
            if (advanced) return;
            // The realm and the tenant come off the credential itself, so nothing had to be threaded
            // down here from the request: a stored credential already knows where it belongs.
            return new SecurityEventService(boundDb as Db).record({
              realmId: credential.realmId,
              tenantId: credential.tenantId,
              category: 'credential',
              action: 'credential.clone_suspected',
              outcome: 'failure',
              cause: 'sign_count_did_not_advance',
              subjectId: credential.subjectId,
              target: { type: 'credential', ref: credentialId },
              detail: { expected: (credential.signCount ?? 0) + 1 },
            });
          })
          .catch(() => {});
      }
      return ok;
    } catch {
      // A malformed key or signature is a refusal, not an error to propagate: the caller asked
      // whether this proof holds, and it does not.
      return false;
    }
  },

  async issue() {
    // A public key is registered by its holder, never minted here. Saying so is better than
    // returning something that looks like a credential and is not.
    return null;
  },
};
