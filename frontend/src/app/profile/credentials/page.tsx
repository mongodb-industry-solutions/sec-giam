'use client';

import { useCallback, useEffect, useState } from 'react';
import { apiUrl } from '../../../lib/env';
import { storedToken } from '../../../lib/session';

/**
 * The authenticators a person has registered, and the ability to retire one.
 *
 * This is where somebody who has lost a device comes, so retiring one is the primary action and it
 * is deliberately easy to reach. The risk of an unnecessary revocation is that the person registers
 * a new device; the risk of a hard-to-reach one is that a lost device keeps working.
 *
 * Retired rather than deleted, so a later question about what could sign at a given moment still has
 * an answer.
 */

const DEFAULT_REALM = 'leafypay';

interface Credential {
  credentialId: string;
  algorithm: string;
  label?: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string;
}

export default function CredentialsPage() {
  const [realm] = useState(DEFAULT_REALM);
  const [token, setToken] = useState('');
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    setToken(storedToken());
  }, []);

  const load = useCallback(async (bearer: string) => {
    if (!bearer) return;
    try {
      const response = await fetch(apiUrl(`/realms/${realm}/credentials`), {
        headers: { authorization: `Bearer ${bearer}` },
        cache: 'no-store',
      });
      if (!response.ok) {
        setError(response.status === 401
          ? 'That session is not valid any more. Sign in again.'
          : 'Your authenticators could not be loaded.');
        return;
      }
      const body = await response.json();
      setCredentials(body.credentials ?? []);
      setError(null);
    } catch {
      setError('The identity service could not be reached.');
    } finally {
      setLoaded(true);
    }
  }, [realm]);

  useEffect(() => { void load(token); }, [token, load]);

  async function retire(credentialId: string) {
    // Confirmed, because it cannot be undone by the person who did it: a retired authenticator is
    // re-registered, not restored.
    if (!window.confirm('Retire this authenticator? It will stop working immediately.')) return;
    const response = await fetch(apiUrl(`/realms/${realm}/credentials/${encodeURIComponent(credentialId)}`), {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
    });
    if (response.ok) {
      await load(token);
    } else {
      setError('That authenticator could not be retired.');
    }
  }

  if (!token) {
    return (
      <main className="min-h-screen flex items-center justify-center p-8">
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-xl font-semibold text-mongodb-dark">Sign in first</h1>
          <p className="mt-2 text-sm text-gray-600">
            These are your own authenticators, so this page needs to know who you are.
          </p>
          <a href="/auth/login" className="mt-6 inline-block text-sm underline">Go to sign in</a>
        </div>
      </main>
    );
  }

  const active = credentials.filter((credential) => credential.status === 'active');

  return (
    <main className="min-h-screen bg-gray-50 p-8">
      <div className="mx-auto max-w-2xl">
        <h1 className="text-2xl font-semibold text-mongodb-dark">Your authenticators</h1>
        <p className="mt-2 text-sm text-gray-600">
          Devices that can approve a sign-in for you. Only the public half of each key is ever stored
          here, so this list cannot be used to sign in as you.
        </p>

        {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

        <div className="mt-6 space-y-3">
          {credentials.map((credential) => (
            <div
              key={credential.credentialId}
              className={`flex items-center justify-between rounded-lg border bg-white p-4 ${
                credential.status === 'revoked' ? 'opacity-60' : ''
              }`}
            >
              <div className="min-w-0">
                <p className="font-medium text-mongodb-dark">{credential.label ?? 'Unnamed device'}</p>
                <p className="mt-1 text-xs text-gray-500">
                  {credential.algorithm} · registered {new Date(credential.createdAt).toLocaleDateString()}
                  {credential.lastUsedAt && ` · last used ${new Date(credential.lastUsedAt).toLocaleDateString()}`}
                </p>
              </div>
              {credential.status === 'active' ? (
                <button
                  type="button"
                  onClick={() => retire(credential.credentialId)}
                  className="shrink-0 rounded-md border border-red-200 px-3 py-1.5 text-sm text-red-700 hover:bg-red-50"
                >
                  Retire
                </button>
              ) : (
                <span className="shrink-0 text-xs uppercase tracking-wide text-gray-400">Retired</span>
              )}
            </div>
          ))}

          {loaded && credentials.length === 0 && (
            <p className="rounded-lg border bg-white p-8 text-center text-sm text-gray-500">
              You have not registered an authenticator yet.
            </p>
          )}
        </div>

        {loaded && active.length === 1 && (
          // Said before it matters rather than after. Somebody with one device discovers the problem
          // at the worst possible moment, which is when that device is gone.
          <p className="mt-6 rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
            This is your only active authenticator. If you lose it you will need help to get back in,
            so registering a second one now is worth the minute it takes.
          </p>
        )}
      </div>
    </main>
  );
}
