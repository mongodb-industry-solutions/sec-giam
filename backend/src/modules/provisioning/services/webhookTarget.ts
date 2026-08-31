import { Db } from 'mongodb';
import { createHmac } from 'crypto';
import type { ProvisioningTarget } from '../../../shared/ports';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';
import { ClientRecord } from '../../oauth/models/client.model';
import { derivedSecret } from '../../../shared/services/secrets';
import { appendLog } from '../../../shared/services/logBuffer';

/**
 * Telling consuming applications that a principal's lifecycle changed.
 *
 * A suspension here has to reach runtime authorization without waiting for a review cycle, and the
 * short access-token lifetime alone is not enough: a token issued a minute before a suspension is
 * still valid, and a resource server verifying locally has no reason to doubt it. So the change is
 * pushed.
 *
 * Delivery is best effort AND reconcilable, which is the pairing that matters. Best effort alone
 * loses a suspension whenever an endpoint is down. Reconciliation alone leaves a window as long as
 * the reconciliation interval. Together, the push covers the common case in seconds and the
 * reconciliation covers the case where the push failed.
 *
 * What this never does is treat a delivery failure as a reason not to make the change. A consumer
 * that cannot be told must not be able to keep a suspended principal active.
 */

let boundDb: Db | null = null;

export function bindProvisioningTargets(db: Db): void {
  boundDb = db;
}

export interface ProvisioningNotice {
  operation: 'create' | 'update' | 'deactivate';
  subjectId: string;
  realmId: string;
  /** Rises on every change, so a receiver can discard one that arrives out of order. */
  version: number;
  payload: Record<string, unknown>;
  sentAt: string;
}

/**
 * Signs the body so a receiver can tell a genuine notice from anything else that reaches its URL.
 *
 * A provisioning webhook that carries "deactivate this principal" and is not authenticated is a
 * denial-of-service endpoint published to the internet.
 */
export function signNotice(body: string): string {
  return createHmac('sha256', derivedSecret('provisioning')).update(body).digest('hex');
}

async function receivers(realmId: string): Promise<ClientRecord[]> {
  if (!boundDb) return [];
  return boundDb
    .collection<ClientRecord>(CLIENT_COLLECTION)
    .find(
      { realmId, status: 'active', 'provisioning.endpoint': { $exists: true } },
      { projection: { _id: 0 } },
    )
    .toArray() as unknown as Promise<ClientRecord[]>;
}

export const webhookProvisioningTarget: ProvisioningTarget = {
  name: 'webhook',

  async push(operation, subjectId, payload) {
    const realmId = String(payload.realmId ?? '');
    const targets = await receivers(realmId);
    if (targets.length === 0) return;

    const notice: ProvisioningNotice = {
      operation,
      subjectId,
      realmId,
      version: Number(payload.version ?? 0),
      // Only what a consumer needs to act. A provisioning notice is not a route for personal data to
      // travel to systems that had no reason to hold it.
      payload: {
        active: payload.active,
        lifecycleState: payload.lifecycleState,
        ...(payload.userName ? { userName: payload.userName } : {}),
      },
      sentAt: new Date().toISOString(),
    };
    const body = JSON.stringify(notice);
    const signature = signNotice(body);

    await Promise.all(targets.map(async (client) => {
      const endpoint = (client as ClientRecord & { provisioning?: { endpoint?: string } }).provisioning?.endpoint;
      if (!endpoint) return;
      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-giam-signature': signature,
            'x-giam-event': `identity.${operation}`,
          },
          body,
          signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) {
          // Recorded rather than retried here. A retry loop inside a lifecycle write is how a slow
          // receiver turns into a slow deprovisioning, and reconciliation is what closes the gap.
          appendLog(`WARN provisioning notice to ${client.clientId} answered ${response.status}; reconciliation will correct it`);
        }
      } catch {
        appendLog(`WARN provisioning notice to ${client.clientId} could not be delivered; reconciliation will correct it`);
      }
    }));
  },
};
