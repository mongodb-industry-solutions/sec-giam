import { createHash, randomBytes } from 'crypto';
import { config } from '../../config';
import { appendLog } from './logBuffer';

/**
 * Server-held keys for the places the authority keys something itself.
 *
 * Each purpose gets its OWN key, derived from one configured secret with the purpose mixed in. That
 * separation matters: a digest keyed for one purpose must not verify for another, or a value minted
 * as a registration challenge could be presented wherever else the same key is used.
 *
 * With nothing configured, a random key is generated for the process and the weakness is REPORTED
 * rather than refused. A single instance then works out of the box; several instances will not agree,
 * which is why it warns. This is configuration, not an environment check: the same build behaves the
 * same way everywhere, and what differs is what you set.
 */

let ephemeralRoot: string | undefined;
const derived = new Map<string, string>();

function root(): string {
  const configured = config.kms.localMasterKey ?? config.app.adminToken;
  if (configured) return configured;
  if (!ephemeralRoot) {
    ephemeralRoot = randomBytes(32).toString('base64');
    appendLog(
      'WARN No signing secret is configured, so keyed values use a per-process key. '
      + 'They will not verify across replicas or restarts. Set GIAM_KMS_LOCAL_MASTER_KEY.',
    );
  }
  return ephemeralRoot;
}

/** The key for one purpose. Cached, because the derivation is deterministic and per-call hashing is waste. */
export function derivedSecret(purpose: string): string {
  const cached = derived.get(purpose);
  if (cached) return cached;
  const key = createHash('sha256').update(`${purpose}:${root()}`).digest('base64');
  derived.set(purpose, key);
  return key;
}

/** Whether the keys are stable across replicas, so the posture report can say so. */
export function secretsAreShared(): boolean {
  return Boolean(config.kms.localMasterKey ?? config.app.adminToken);
}
