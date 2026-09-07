'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Building2 } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Fact } from '../../../../components/Fact';
import { ErrorState, LoadingState } from '../../../../components/ResultState';
import { ApiError, callApi, can, currentClaims } from '../../../../lib/console';
import { usePermissions } from '../../../../lib/profile';
import { Field, INPUT } from '../../roles/parts';

interface Realm {
  realmId: string;
  name: string;
  displayName: string;
  issuer: string;
  enabled: boolean;
  demoMode: boolean;
  notice?: string;
  tokenPolicy: {
    accessTokenTtlSeconds: number;
    refreshTokenTtlSeconds: number;
    codeTtlSeconds: number;
    sessionIdleTtlSeconds: number;
    sessionMaxTtlSeconds: number;
  };
}

/**
 * One realm's own configuration, not what lives inside it.
 *
 * `name` is not editable here: it is embedded in the issuer URL every token already carries, so
 * changing it would be a new realm wearing an old one's identifier rather than an edit.
 */
export default function RealmDetailPage() {
  const params = useParams<{ name: string }>();
  const name = decodeURIComponent(String(params.name ?? ''));

  const [realm, setRealm] = useState<Realm | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [displayName, setDisplayName] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [demoMode, setDemoMode] = useState(false);
  const [notice, setNotice] = useState('');
  const [accessTokenTtl, setAccessTokenTtl] = useState(300);

  usePermissions();
  const mayManage = can(currentClaims(), 'realms', 'manage');

  const load = useCallback(async () => {
    if (!name) return;
    setLoading(true);
    try {
      const record = await callApi<Realm>(`/realms/${encodeURIComponent(name)}`, { subject: 'that realm' });
      setRealm(record);
      setDisplayName(record.displayName);
      setEnabled(record.enabled);
      setDemoMode(record.demoMode);
      setNotice(record.notice ?? '');
      setAccessTokenTtl(record.tokenPolicy.accessTokenTtlSeconds);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That realm could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [name]);

  useEffect(() => { void load(); }, [load]);

  async function save() {
    setBusy(true);
    try {
      const updated = await callApi<Realm>(`/realms/${encodeURIComponent(name)}`, {
        method: 'PATCH',
        subject: 'that realm',
        body: {
          displayName,
          enabled,
          demoMode,
          ...(notice ? { notice } : {}),
          tokenPolicy: { accessTokenTtlSeconds: accessTokenTtl },
        },
      });
      setRealm(updated);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That change could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="space-y-5">
      <Link
        href="/system/realms"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All realms
      </Link>

      <SectionHeader
        icon={Building2}
        title={realm?.displayName || name || 'Realm'}
        description={realm ? realm.issuer : 'One realm.'}
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && <LoadingState label="Reading this realm…" />}

      {realm && !loading && (
        <section className="space-y-4 rounded-xl border border-gray-200 bg-white p-5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Settings</h2>

          <dl className="grid gap-3 text-sm sm:grid-cols-2">
            <Fact label="Slug" value={realm.name} mono />
            <Fact label="Realm id" value={realm.realmId} mono />
          </dl>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Display name">
              <input value={displayName} disabled={!mayManage} onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
            </Field>

            <label className="mt-6 flex items-center gap-2 text-sm text-gray-700">
              <input
                type="checkbox"
                checked={enabled}
                disabled={!mayManage}
                onChange={(e) => setEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-gray-300"
              />
              Enabled
              <Tooltip text="Disabling a realm refuses every token it would otherwise issue or verify. Reversible: the realm, its principals and its clients are all still here." />
            </label>
          </div>

          <Field label="Login banner" hint="Shown on the sign-in screen for this realm. Optional.">
            <input value={notice} disabled={!mayManage} onChange={(e) => setNotice(e.target.value)} className={INPUT} />
          </Field>

          <label className="flex items-center gap-2 text-sm text-gray-700">
            <input
              type="checkbox"
              checked={demoMode}
              disabled={!mayManage}
              onChange={(e) => setDemoMode(e.target.checked)}
              className="h-4 w-4 rounded border-gray-300"
            />
            Demo mode
            <Tooltip text="Allows the demo simulator to exchange a token to act as a persona in this realm. A production realm should never have this on, whatever the process was started with." />
          </label>

          <Field label="Access token lifetime (seconds)" hint="The revocation objective: this is the longest a revoked session's tokens keep working, since a token is verified without touching the database.">
            <input
              type="number"
              min={60}
              value={accessTokenTtl}
              disabled={!mayManage}
              onChange={(e) => setAccessTokenTtl(Number(e.target.value))}
              className={INPUT}
            />
          </Field>

          {mayManage && (
            <button
              type="button"
              disabled={busy}
              onClick={() => void save()}
              className="rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:opacity-90 disabled:opacity-50"
            >
              {busy ? 'Saving…' : 'Save'}
            </button>
          )}
        </section>
      )}
    </main>
  );
}
