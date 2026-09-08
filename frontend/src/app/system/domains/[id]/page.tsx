'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Globe, Plus, Trash2, UsersRound } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Fact } from '../../../../components/RecordCard';
import { ErrorState, LoadingState } from '../../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../../lib/console';
import { usePermissions } from '../../../../lib/profile';
import { Field, INPUT } from '../../roles/parts';

/**
 * One authentication path: its settings, and (for a federated one) what its claims mean here.
 *
 * The upstream provider says who signed in. It never says what they may do: `claimMappings` is the
 * only bridge between an upstream group name and a local role, so it is edited here rather than left
 * to whatever the provider happens to assert.
 */

interface Domain {
  domainId: string;
  name: string;
  displayName: string;
  protocol: string;
  adapter: string;
  enabled: boolean;
  notice?: string;
  hasClientSecret: boolean;
  claimMappings: Array<{ claim: string; value: string; roleName: string }>;
  registration?: { selfServiceEnabled: boolean; autoApprove: boolean };
  authentication?: { cibaEnabled?: boolean };
  createdAt?: string;
  lastModifiedAt?: string;
}

export default function DomainDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = decodeURIComponent(String(params.id ?? ''));

  const [domain, setDomain] = useState<Domain | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Draft fields, so a half-finished edit never becomes a request until "Save" is pressed.
  const [displayName, setDisplayName] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [notice, setNotice] = useState('');
  const [selfService, setSelfService] = useState(false);
  const [autoApprove, setAutoApprove] = useState(false);
  const [cibaEnabled, setCibaEnabled] = useState(true);
  const [mappings, setMappings] = useState<Array<{ claim: string; value: string; roleName: string }>>([]);

  usePermissions();
  const mayManage = can(currentClaims(), 'providers', 'manage');

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      const record = await callApi<Domain>(`/domains/${encodeURIComponent(id)}`, { subject: 'that authentication path' });
      setDomain(record);
      setDisplayName(record.displayName);
      setEnabled(record.enabled);
      setNotice(record.notice ?? '');
      setSelfService(record.registration?.selfServiceEnabled ?? false);
      setAutoApprove(record.registration?.autoApprove ?? false);
      setCibaEnabled(record.authentication?.cibaEnabled ?? true);
      setMappings(record.claimMappings ?? []);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authentication path could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function save() {
    setBusy(true);
    try {
      const updated = await callApi<Domain>(`/domains/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        subject: 'that authentication path',
        body: {
          displayName,
          enabled,
          ...(notice ? { notice } : {}),
          registration: { selfServiceEnabled: selfService, autoApprove: selfService && autoApprove },
          authentication: { cibaEnabled },
          claimMappings: mappings.filter((m) => m.claim && m.value && m.roleName),
        },
      });
      setDomain(updated);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That change could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!domain) return;
    if (!window.confirm(`Delete "${domain.displayName}"? Anybody who signs in only through this path loses their way in.`)) return;
    setBusy(true);
    try {
      await callApi(`/domains/${encodeURIComponent(id)}`, { method: 'DELETE', subject: 'that authentication path' });
      router.push('/system/domains');
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authentication path could not be deleted.');
      setBusy(false);
    }
  }

  function addMapping() {
    setMappings((current) => [...current, { claim: '', value: '', roleName: '' }]);
  }

  function updateMapping(index: number, patch: Partial<{ claim: string; value: string; roleName: string }>) {
    setMappings((current) => current.map((m, i) => (i === index ? { ...m, ...patch } : m)));
  }

  function removeMapping(index: number) {
    setMappings((current) => current.filter((_, i) => i !== index));
  }

  const isFederated = domain?.protocol !== 'internal';

  return (
    <main className="space-y-5">
      <Link
        href="/system/domains"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All authentication paths
      </Link>

      <SectionHeader
        icon={Globe}
        title={domain?.displayName || domain?.name || 'Authentication path'}
        description={domain ? `${domain.protocol} · ${domain.adapter}` : 'One authentication path.'}
        actions={domain
          ? (
            <Link
              href={`/system/identities?domainId=${encodeURIComponent(domain.domainId)}`}
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-300 px-3 py-1.5 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50"
            >
              <UsersRound size={13} aria-hidden />
              Principals on this path
            </Link>
          )
          : undefined}
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && <LoadingState label="Reading this authentication path…" />}

      {domain && !loading && (
        <>
          <section className="space-y-4 rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Settings</h2>

            <dl className="grid gap-3 text-sm sm:grid-cols-3">
              <Fact label="Slug" value={domain.name} />
              <Fact label="Created" value={when(domain.createdAt)} />
              <Fact label="Last changed" value={when(domain.lastModifiedAt)} />
            </dl>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Display name">
                <input
                  value={displayName}
                  disabled={!mayManage}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className={INPUT}
                />
              </Field>

              <label className="mt-6 flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={enabled}
                  disabled={!mayManage}
                  onChange={(e) => setEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-gray-300"
                />
                Enabled (shown in the sign-in selector)
              </label>
            </div>

            <Field label="Login banner" hint="Shown above the sign-in form for this path. Optional.">
              <input value={notice} disabled={!mayManage} onChange={(e) => setNotice(e.target.value)} className={INPUT} />
            </Field>

            <div className="space-y-2 border-t border-gray-100 pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Self-registration</h3>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={selfService}
                  disabled={!mayManage}
                  onChange={(e) => setSelfService(e.target.checked)}
                  className="h-4 w-4 rounded border-gray-300"
                />
                Allow a person to create their own account on this path
              </label>
              {selfService && (
                <label className="ml-6 flex items-center gap-2 text-sm text-gray-700">
                  <input
                    type="checkbox"
                    checked={autoApprove}
                    disabled={!mayManage}
                    onChange={(e) => setAutoApprove(e.target.checked)}
                    className="h-4 w-4 rounded border-gray-300"
                  />
                  Auto-approve: activate immediately, skip manager review
                </label>
              )}
            </div>

            <div className="space-y-2 border-t border-gray-100 pt-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Backchannel authentication</h3>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={cibaEnabled}
                  disabled={!mayManage}
                  onChange={(e) => setCibaEnabled(e.target.checked)}
                  className="h-4 w-4 rounded border-gray-300"
                />
                Allow CIBA sign-in for a principal identified through this path
                <Tooltip text="A principal already registered a device key elsewhere may still be reached by CIBA unless this is off. It does not affect client_credentials: that authenticates a workload, not a person, and has no domain to check." />
              </label>
            </div>

            {isFederated && (
              <div className="space-y-2 border-t border-gray-100 pt-4">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-600">
                  Claim to role mapping
                </h3>
                <p className="text-xs text-gray-500">
                  What this provider asserts, translated into a role of this realm. Nothing else it
                  asserts grants anything here.
                </p>
                {mappings.map((mapping, index) => (
                  <div key={index} className="grid grid-cols-[1fr_1fr_1fr_auto] items-end gap-2">
                    <Field label="Claim">
                      <input
                        value={mapping.claim}
                        disabled={!mayManage}
                        onChange={(e) => updateMapping(index, { claim: e.target.value })}
                        placeholder="groups"
                        className={INPUT}
                      />
                    </Field>
                    <Field label="Value">
                      <input
                        value={mapping.value}
                        disabled={!mayManage}
                        onChange={(e) => updateMapping(index, { value: e.target.value })}
                        placeholder="fraud-team"
                        className={INPUT}
                      />
                    </Field>
                    <Field label="Grants role">
                      <input
                        value={mapping.roleName}
                        disabled={!mayManage}
                        onChange={(e) => updateMapping(index, { roleName: e.target.value })}
                        placeholder="level1_analyst"
                        className={INPUT}
                      />
                    </Field>
                    {mayManage && (
                      <button
                        type="button"
                        onClick={() => removeMapping(index)}
                        aria-label="Remove this mapping"
                        className="mb-1 rounded-md border border-gray-200 p-2 text-gray-400 hover:bg-gray-50 hover:text-red-600"
                      >
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                ))}
                {mayManage && (
                  <button
                    type="button"
                    onClick={addMapping}
                    className="inline-flex items-center gap-1.5 rounded-md border border-gray-300 px-2.5 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50"
                  >
                    <Plus size={12} aria-hidden />
                    Add a mapping
                  </button>
                )}
              </div>
            )}

            {mayManage && (
              <div className="flex items-center gap-2 border-t border-gray-100 pt-4">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void save()}
                  className="rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:opacity-90 disabled:opacity-50"
                >
                  {busy ? 'Saving…' : 'Save'}
                </button>
              </div>
            )}
          </section>

          {mayManage && (
            <section className="rounded-xl border border-red-200 bg-red-50 p-5">
              <h2 className="text-sm font-semibold text-red-800">Delete this authentication path</h2>
              <p className="mt-1 text-xs text-red-700">
                Refused when it is the only enabled path in this realm, which would leave nobody able
                to sign in, including you.
              </p>
              <button
                type="button"
                disabled={busy}
                onClick={() => void remove()}
                className="mt-3 inline-flex items-center gap-1.5 rounded-md border border-red-300 px-3 py-1.5 text-xs font-medium text-red-700 hover:bg-red-100 disabled:opacity-50"
              >
                <Trash2 size={13} aria-hidden />
                Delete
              </button>
            </section>
          )}
        </>
      )}
    </main>
  );
}
