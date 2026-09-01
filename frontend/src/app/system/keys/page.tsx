'use client';

import { useCallback } from 'react';
import { KeySquare, RefreshCw, ShieldOff } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { EmptyState, ErrorState, LoadingState } from '../../../components/ResultState';
import { ActionButton, Fact, RecordCard } from '../../../components/RecordCard';
import { callApi, can, currentClaims, when } from '../../../lib/console';
import { useConsoleResource } from '../../../lib/useConsoleResource';

/**
 * The realm's signing keys, and what each one is currently for.
 *
 * The distinction the screen exists to make is between a key that is SIGNING and one that is merely
 * still PUBLISHED. A replica that went away leaves its key behind on purpose: the tokens it signed
 * have not expired, and removing the key early would sign those people out. That is invisible in the
 * raw record and is the first thing an operator needs to see here.
 *
 * No private material appears anywhere on this screen because none of it reaches the database.
 */

type Phase = 'signing' | 'published' | 'retired' | 'revoked';

interface KeyView {
  kid: string;
  keyId: string;
  algorithm: string;
  use: string;
  keySize?: number;
  provider: string;
  status: string;
  phase: Phase;
  phaseReason: string;
  instanceId?: string;
  ownedByThisInstance: boolean;
  externalCustody: boolean;
  leaseExpiresAt?: string;
  leaseLapsed: boolean;
  signingEligible: boolean;
  notBefore: string;
  notAfter?: string;
  rotatedAt?: string;
}

interface KeySet {
  keys: KeyView[];
  provider: string;
  externalCustody: boolean;
  rotatable: boolean;
  instanceId: string;
  leaseSeconds?: number;
  publicationGraceSeconds?: number;
}

const PHASE_TONE: Record<Phase, string> = {
  signing: 'border-emerald-200 bg-emerald-50 text-emerald-700',
  published: 'border-blue-200 bg-blue-50 text-blue-700',
  retired: 'border-gray-200 bg-gray-50 text-gray-600',
  revoked: 'border-red-200 bg-red-50 text-red-700',
};

export default function KeysPage() {
  const read = useCallback(
    () => callApi<KeySet>('/signing-keys', { subject: 'this realm\'s signing keys' }),
    [],
  );
  const keys = useConsoleResource(read, 'The signing keys could not be read.');

  const claims = currentClaims();
  const mayRotate = can(claims, 'keys', 'rotate');
  const mayRetire = can(claims, 'keys', 'retire');
  const set = keys.data;

  async function rotate() {
    if (!window.confirm(
      'Rotate this replica\'s signing key? The new key is published before the old one stops signing, '
      + 'and the old one keeps verifying until its grace period ends.',
    )) return;
    await keys.run(
      'rotate',
      () => callApi('/signing-keys/rotate', { method: 'POST', subject: 'that key' }),
      'The key could not be rotated.',
    );
  }

  async function retire(key: KeyView) {
    const stillPublished = key.phase === 'signing' || key.phase === 'published';
    if (!window.confirm(stillPublished
      ? 'Withdraw this key from the published set? Every token already signed with it stops verifying '
        + 'immediately, so anybody holding one is signed out at their next request.'
      : 'Withdraw this key from the published set?')) return;

    await keys.run(
      key.kid,
      () => callApi(`/signing-keys/${encodeURIComponent(key.kid)}/retire`, {
        method: 'POST',
        // The API refuses without this while live tokens depend on the key, and the confirmation
        // above is what the acknowledgement means. Sending it unasked would defeat the refusal.
        body: { acknowledgeTokenBreakage: stillPublished },
        subject: 'that key',
      }),
      'That key could not be retired.',
    );
  }

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={KeySquare}
        title="Signing keys"
        description="What this realm signs with, what still verifies, and which replica holds each private half."
        info={
          <>
            Each replica holds its own private key and publishes only the public half, so the realm&apos;s
            key set is the union and a token signed by one replica verifies at every other. A key whose
            lease has lapsed stops signing but stays published, because the tokens it already signed
            have not expired.
          </>
        }
        actions={set && mayRotate && set.rotatable
          ? <ActionButton icon={RefreshCw} label="Rotate this replica's key" busy={keys.busy === 'rotate'} onClick={() => void rotate()} />
          : undefined}
      />

      {keys.error && <ErrorState message={keys.error} onRetry={() => void keys.reload()} />}

      {set && (
        <p className="text-xs text-gray-500">
          Custody: <span className="font-medium text-gray-700">{set.provider}</span>
          {set.externalCustody
            ? '. The private key is held outside this deployment, so rotation belongs where it lives.'
            : `. This replica is ${set.instanceId}.`}
          {set.publicationGraceSeconds
            ? ` A lapsed key stays published for ${Math.round(set.publicationGraceSeconds / 60)} minutes.`
            : ''}
        </p>
      )}

      {keys.loading && !set
        ? <LoadingState label="Reading the key set…" />
        : (set?.keys ?? []).length === 0
          ? <EmptyState
              icon={KeySquare}
              title="This realm publishes no keys"
              description="Nothing can be signed or verified for this realm until a replica publishes one."
            />
          : (
            <ul className="space-y-3">
              {(set?.keys ?? []).map((key) => (
                <RecordCard
                  key={key.kid}
                  title={key.keyId}
                  subtitle={key.kid}
                  badges={
                    <>
                      <Tooltip text={key.phaseReason}>
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${PHASE_TONE[key.phase]}`}>
                          {key.phase}
                        </span>
                      </Tooltip>
                      {key.ownedByThisInstance && (
                        <Tooltip text="This replica holds the private half, so it is the one that can rotate it.">
                          <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-600">
                            this replica
                          </span>
                        </Tooltip>
                      )}
                    </>
                  }
                  facts={
                    <>
                      <Fact label="Algorithm" value={`${key.algorithm}${key.keySize ? ` · ${key.keySize} bit` : ''}`} />
                      <Fact
                        label="Held by"
                        value={key.instanceId ?? 'external custody'}
                        title={key.instanceId ?? 'The private key is held outside this deployment.'}
                      />
                      <Fact label="Custody" value={key.provider} />
                      <Fact label="Published since" value={when(key.notBefore)} />
                      <Fact
                        label="Lease"
                        value={key.leaseExpiresAt ? `${key.leaseLapsed ? 'lapsed ' : 'renews '}${when(key.leaseExpiresAt)}` : 'no lease'}
                      />
                      <Fact
                        label="Published until"
                        value={key.notAfter ? when(key.notAfter) : 'while its lease holds'}
                      />
                    </>
                  }
                  actions={mayRetire && (key.phase === 'signing' || key.phase === 'published')
                    ? (
                      <ActionButton
                        icon={ShieldOff}
                        label="Retire"
                        tone="danger"
                        busy={keys.busy === key.kid}
                        onClick={() => void retire(key)}
                      />
                    )
                    : undefined}
                >
                  <p className="mt-2 text-sm text-gray-600">{key.phaseReason}</p>
                </RecordCard>
              ))}
            </ul>
          )}
    </main>
  );
}
