'use client';

import { useCallback, useEffect, useState } from 'react';
import { KeyRound, Trash2 } from 'lucide-react';
import { EmptyState, ErrorState, LoadingState, StatusBadge } from './ResultState';
import { Tooltip } from './Tooltip';
import { ApiError, callApi, when } from '../lib/console';

/**
 * The authenticators a person has registered, and the ability to retire one.
 *
 * This is where somebody who has lost a device comes, so retiring one is the primary action and it
 * is deliberately easy to reach. The risk of an unnecessary revocation is that the person registers
 * a new device; the risk of a hard-to-reach one is that a lost device keeps working.
 *
 * Retired rather than deleted, so a later question about what could sign at a given moment still has
 * an answer. One component, used by the console and by the standalone profile page, so the two can
 * never drift.
 */

export interface Credential {
  credentialId: string;
  algorithm: string;
  label?: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string;
}

export function CredentialsPanel({ onCount }: { onCount?: (active: number) => void }) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const body = await callApi<{ credentials: Credential[] }>('/credentials', { subject: 'your authenticators' });
      setCredentials(body.credentials ?? []);
      onCount?.((body.credentials ?? []).filter((one) => one.status === 'active').length);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'Your authenticators could not be loaded.');
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function retire(credential: Credential) {
    // Confirmed, because it cannot be undone by the person who did it: a retired authenticator is
    // re-registered, not restored.
    if (!window.confirm('Retire this authenticator? It will stop working immediately.')) return;
    setBusy(credential.credentialId);
    try {
      await callApi(`/credentials/${encodeURIComponent(credential.credentialId)}`, {
        method: 'DELETE',
        subject: 'that authenticator',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authenticator could not be retired.');
    } finally {
      setBusy(null);
    }
  }

  if (loading) return <LoadingState label="Reading your authenticators…" />;

  return (
    <div className="space-y-3">
      {error && <ErrorState message={error} onRetry={() => void load()} />}

      {credentials.length === 0
        ? <EmptyState
            icon={KeyRound}
            title="No authenticators registered"
            description="Nothing can approve a sign-in for you yet. An authenticator is registered from the device that will hold it, and appears here once it is."
          />
        : (
          <ul className="space-y-3">
            {credentials.map((credential) => (
              <li
                key={credential.credentialId}
                className={`flex flex-wrap items-center justify-between gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm ${
                  credential.status !== 'active' ? 'opacity-70' : ''
                }`}
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold text-[#001E2B]">{credential.label ?? 'Unnamed device'}</p>
                    <StatusBadge status={credential.status} />
                    <Tooltip text="The signature algorithm this device uses. Only the public half of the key is ever stored here, so this list cannot be used to sign in as you." >
                      <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-600">
                        {credential.algorithm}
                      </span>
                    </Tooltip>
                  </div>
                  <p className="mt-1.5 text-xs text-gray-500">
                    Registered {when(credential.createdAt)} · last used {when(credential.lastUsedAt)}
                  </p>
                  <p className="mt-0.5 font-mono text-[10px] text-gray-400">{credential.credentialId}</p>
                </div>

                {credential.status === 'active' && (
                  <button
                    type="button"
                    disabled={busy === credential.credentialId}
                    onClick={() => void retire(credential)}
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                  >
                    <Trash2 size={12} aria-hidden />
                    Retire
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
    </div>
  );
}
