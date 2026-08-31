'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, UserCheck, UserMinus, UserRound } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Fact } from '../../../../components/Fact';
import { ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ApiError, callApi, when } from '../../../../lib/console';
import { ScimUser, extensionOf, primaryEmail } from '../../../../lib/identities';

/**
 * One principal, and the two things that can be done to it from here.
 *
 * Correcting a record and ending its access are provisioning acts. Granting authority is not one, and
 * there is deliberately no control for it: roles are assigned elsewhere, so administering the
 * directory can never become a way to grant yourself something.
 */
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

export default function IdentityDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = decodeURIComponent(String(params.id ?? ''));

  const [user, setUser] = useState<ScimUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);

  const load = useCallback(async () => {
    if (!id) return;
    setLoading(true);
    try {
      setUser(await callApi<ScimUser>(`/scim/v2/Users/${encodeURIComponent(id)}`, { subject: 'that principal' }));
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That principal could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function patch(value: Record<string, unknown>, subject: string) {
    setBusy(true);
    try {
      const answer = await callApi<ScimUser>(`/scim/v2/Users/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        subject,
        body: { schemas: [PATCH_SCHEMA], Operations: [{ op: 'replace', value }] },
      });
      setUser(answer);
      setError(null);
      return true;
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That change could not be saved.');
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function setActive(active: boolean) {
    if (!active && !window.confirm(
      'Deactivate this principal? Every token already issued stops working immediately, not at its expiry.',
    )) return;
    await patch({ active }, 'that principal');
  }

  async function deprovision() {
    if (!window.confirm(
      'Deprovision this principal? The record is retired rather than deleted, so the audit trail still resolves, and everything outstanding stops working now.',
    )) return;
    setBusy(true);
    try {
      await callApi(`/scim/v2/Users/${encodeURIComponent(id)}`, { method: 'DELETE', subject: 'that principal' });
      router.push('/system/identities');
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That principal could not be deprovisioned.');
      setBusy(false);
    }
  }

  const extension = extensionOf(user);
  const retired = extension.lifecycleState === 'deprovisioned';

  return (
    <main className="space-y-5">
      <Link
        href="/system/identities"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 transition-colors hover:text-[#001E2B] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
      >
        <ArrowLeft size={13} aria-hidden />
        All principals
      </Link>

      <SectionHeader
        icon={UserRound}
        title={user?.name?.formatted || user?.userName || id || 'Principal'}
        description={user ? `Recorded ${when(user.meta?.created)}` : 'One principal in the directory.'}
        actions={user ? <StatusBadge status={extension.lifecycleState || (user.active ? 'active' : 'inactive')} /> : undefined}
      />

      {error && <ErrorState message={error} onRetry={() => void load()} />}
      {loading && <LoadingState label="Reading this principal…" />}

      {user && !loading && (
        <>
          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">The principal</h2>
            <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
              <Fact label="Subject" value={user.id} mono />
              <Fact label="User name" value={user.userName} />
              <Fact label="External id" value={user.externalId} mono />
              <Fact label="Primary email" value={primaryEmail(user) || 'not set'} />
              <Fact label="Kind" value={extension.kind} />
              <Fact label="Usable" value={user.active ? 'yes' : 'no'} />
              <Fact label="Lifecycle">
                <span className="flex items-center gap-1.5">
                  {extension.lifecycleState ?? 'unknown'}
                  <Tooltip text="A suspended principal and a retired one are both inactive and are not the same thing to anyone reviewing them, which is why the lifecycle is carried separately from the usable flag." />
                </span>
              </Fact>
              <Fact label="Upstream provider" value={extension.providerId} mono />
              <Fact label="Business reference" value={extension.accountHolderRef} mono />
              <Fact label="Last changed" value={when(user.meta?.lastModified)} />
            </dl>
          </section>

          {editing
            ? (
              <EditForm
                user={user}
                busy={busy}
                onCancel={() => setEditing(false)}
                onSave={async (value) => { if (await patch(value, 'that principal')) setEditing(false); }}
              />
            )
            : (
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setEditing(true)}
                  disabled={retired}
                  className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
                >
                  Correct the record
                </button>
                <button
                  type="button"
                  disabled={busy || retired}
                  onClick={() => void setActive(!user.active)}
                  className="inline-flex items-center gap-1.5 rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
                >
                  {user.active
                    ? <><UserMinus size={12} aria-hidden /> Deactivate</>
                    : <><UserCheck size={12} aria-hidden /> Reactivate</>}
                </button>
                <button
                  type="button"
                  disabled={busy || retired}
                  onClick={() => void deprovision()}
                  className="inline-flex items-center gap-1.5 rounded-md border border-red-200 px-3 py-2 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                >
                  <UserMinus size={12} aria-hidden />
                  Deprovision
                </button>
              </div>
            )}
        </>
      )}
    </main>
  );
}

/** The short allowlist a provisioning client may change. Authority is deliberately not on it. */
function EditForm({ user, busy, onCancel, onSave }: {
  user: ScimUser;
  busy: boolean;
  onCancel: () => void;
  onSave: (value: Record<string, unknown>) => void;
}) {
  const [userName, setUserName] = useState(user.userName);
  const [externalId, setExternalId] = useState(user.externalId ?? '');
  const [given, setGiven] = useState(user.name?.givenName ?? '');
  const [family, setFamily] = useState(user.name?.familyName ?? '');
  const [email, setEmail] = useState(primaryEmail(user));

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const formatted = [given.trim(), family.trim()].filter(Boolean).join(' ');
    onSave({
      userName: userName.trim(),
      ...(externalId.trim() ? { externalId: externalId.trim() } : {}),
      ...(formatted
        ? { name: { formatted, ...(given.trim() ? { givenName: given.trim() } : {}), ...(family.trim() ? { familyName: family.trim() } : {}) } }
        : {}),
      ...(email.trim() ? { emails: [{ value: email.trim(), primary: true }] } : {}),
    });
  }

  return (
    <form onSubmit={submit} className="space-y-4 rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
      <h2 className="text-sm font-semibold text-[#001E2B]">Correct the record</h2>
      <p className="text-xs text-gray-500">
        A name, an email and an external id. Nothing here changes what the principal may do.
      </p>

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">User name</span>
          <input
            required
            value={userName}
            onChange={(event) => setUserName(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">External id</span>
          <input
            value={externalId}
            onChange={(event) => setExternalId(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Given name</span>
          <input
            value={given}
            onChange={(event) => setGiven(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Family name</span>
          <input
            value={family}
            onChange={(event) => setFamily(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
        <label className="block sm:col-span-2">
          <span className="text-[10px] uppercase tracking-wider text-gray-400">Primary email</span>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
          />
        </label>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={busy || !userName.trim()}
          className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          Cancel
        </button>
      </div>
    </form>
  );
}
