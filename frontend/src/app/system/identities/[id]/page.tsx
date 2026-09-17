'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft, KeyRound, Layers, Pencil, ShieldHalf, ShieldOff, Trash2, UserCheck, UserMinus, UserRound,
} from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { Tooltip } from '../../../../components/Tooltip';
import { Fact } from '../../../../components/Fact';
import { ErrorState, LoadingState, StatusBadge } from '../../../../components/ResultState';
import { ApiError, callApi, can, currentClaims, when } from '../../../../lib/console';
import { usePermissions } from '../../../../lib/profile';
import { ScimUser, extensionOf, primaryEmail, useDomainNames } from '../../../../lib/identities';
import { useConfirm } from '../../../../components/ConfirmProvider';
import { PasswordRules } from '../../../../components/PasswordRules';
import {
  allMet, evaluatePassword, loadPasswordPolicy, PasswordPolicy,
} from '../../../../lib/passwordPolicy';
import type { RoleSummary } from '../../roles/types';

interface Assignment {
  subjectId: string;
  roleId: string;
  grantedAt: string;
  expiresAt?: string;
  live: boolean;
}

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
  const confirm = useConfirm();
  const id = decodeURIComponent(String(params.id ?? ''));

  const [user, setUser] = useState<ScimUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);

  const [assignments, setAssignments] = useState<Assignment[] | null>(null);
  const [assignmentsError, setAssignmentsError] = useState<string | null>(null);
  const [roleBusy, setRoleBusy] = useState<string | null>(null);
  const [assigning, setAssigning] = useState(false);
  // The catalog this realm defines, read once so a role holding shows a name rather than the
  // identifier nobody but the database reads.
  const [roleCatalog, setRoleCatalog] = useState<RoleSummary[]>([]);

  usePermissions();
  const mayManageAssignments = can(currentClaims(), 'assignments', 'manage');
  const domainName = useDomainNames();

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

  const loadRoles = useCallback(async () => {
    if (!id) return;
    try {
      const body = await callApi<{ assignments: Assignment[] }>(
        `/principals/${encodeURIComponent(id)}/roles`,
        { subject: 'the roles this principal holds' },
      );
      setAssignments(body.assignments);
      setAssignmentsError(null);
    } catch (failure) {
      setAssignmentsError(failure instanceof ApiError ? failure.message : 'The roles held could not be read.');
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void loadRoles(); }, [loadRoles]);
  useEffect(() => {
    // Read once the roles-held call has actually succeeded, which already proves `assignments:view`,
    // and only once: a role is renamed rarely enough that refetching on every grant or revoke would
    // be a request this screen never needed.
    if (assignments === null || roleCatalog.length > 0) return;
    callApi<{ roles: RoleSummary[] }>('/roles', { query: { limit: 200 }, subject: 'the roles this realm defines' })
      .then((body) => setRoleCatalog(body.roles))
      .catch(() => setRoleCatalog([]));
  }, [assignments, roleCatalog.length]);

  const roleName = useCallback(
    (roleId: string) => roleCatalog.find((role) => role.roleId === roleId)?.displayName ?? roleId,
    [roleCatalog],
  );

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
    if (!active && !(await confirm(
      'Deactivate this principal? Every token already issued stops working immediately, not at its expiry.',
    ))) return;
    await patch({ active }, 'that principal');
  }

  async function deprovision() {
    if (!(await confirm(
      'Deprovision this principal? The record is retired rather than deleted, so the audit trail still resolves, and everything outstanding stops working now.',
    ))) return;
    setBusy(true);
    try {
      await callApi(`/scim/v2/Users/${encodeURIComponent(id)}`, { method: 'DELETE', subject: 'that principal' });
      router.push('/system/identities');
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That principal could not be deprovisioned.');
      setBusy(false);
    }
  }

  async function assignRole(roleId: string) {
    setRoleBusy(roleId);
    try {
      await callApi(`/roles/${encodeURIComponent(roleId)}/assignments`, {
        method: 'POST',
        body: { subjectId: id },
        subject: 'that role assignment',
      });
      await loadRoles();
      setAssigning(false);
    } catch (failure) {
      setAssignmentsError(failure instanceof ApiError ? failure.message : 'That role could not be assigned.');
    } finally {
      setRoleBusy(null);
    }
  }

  async function revokeRole(roleId: string) {
    if (!(await confirm('Take this role back? It stops applying at this principal\'s next token.'))) return;
    setRoleBusy(roleId);
    try {
      await callApi(`/principals/${encodeURIComponent(id)}/roles/${encodeURIComponent(roleId)}`, {
        method: 'DELETE',
        subject: 'that role',
      });
      await loadRoles();
    } catch (failure) {
      setAssignmentsError(failure instanceof ApiError ? failure.message : 'That role could not be revoked.');
    } finally {
      setRoleBusy(null);
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
        description={user
          ? `Recorded ${when(user.meta?.created)}${extension.domainId ? ` · ${domainName.name(extension.domainId) ?? 'an authentication path'}` : ''}`
          : 'One principal in the directory.'}
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
              <Fact label="User name">
                <span className="flex items-center gap-1.5">
                  {user.userName}
                  <Tooltip text="What this principal signs in as. Changed here, it changes for every credential this principal holds." />
                </span>
              </Fact>
              <Fact label="External id" value={user.externalId} mono />
              <Fact label="Primary email" value={primaryEmail(user) || 'not set'} />
              <Fact label="Kind">
                <span className="flex items-center gap-1.5">
                  {extension.kind ?? 'unknown'}
                  <Tooltip text="A human, a workload or a service account: what this authority checks are different rules for, carried once rather than guessed from which fields happen to be filled in." />
                </span>
              </Fact>
              <Fact label="Usable">
                <span className="flex items-center gap-1.5">
                  {user.active ? 'yes' : 'no'}
                  <Tooltip text="Whether this principal can authenticate right now. Separate from the lifecycle: a principal can exist and be recorded without being usable." />
                </span>
              </Fact>
              <Fact label="Lifecycle">
                <span className="flex items-center gap-1.5">
                  {extension.lifecycleState ?? 'unknown'}
                  <Tooltip text="A suspended principal and a retired one are both inactive and are not the same thing to anyone reviewing them, which is why the lifecycle is carried separately from the usable flag." />
                </span>
              </Fact>
              <Fact label="Authentication path">
                <span className="flex items-center gap-1.5">
                  {extension.domainId
                    ? (
                      <Link
                        href={`/system/domains/${encodeURIComponent(extension.domainId)}`}
                        className="text-[#001E2B] hover:underline"
                      >
                        {domainName.name(extension.domainId) ?? extension.domainId}
                      </Link>
                    )
                    : 'not recorded'}
                  <Tooltip text="Which directory this principal was provisioned or signed in through. A remote directory's own administrator decides who exists there; this authority only decides what they may do once they arrive." />
                </span>
              </Fact>
              <Fact label="Business reference">
                <span className="flex items-center gap-1.5">
                  {extension.accountHolderRef ?? 'not set'}
                  <Tooltip text="Binds this principal to the party or account it represents in the business domain, for a self-scoped role that reaches only its own records." />
                </span>
              </Fact>
              <Fact label="Last changed" value={when(user.meta?.lastModified)} />
            </dl>
          </section>

          <section className="rounded-xl border border-gray-200 bg-white p-5">
            <div className="flex items-center justify-between">
              <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
                <ShieldHalf size={14} className="text-gray-400" aria-hidden />
                Roles held
              </h2>
              {mayManageAssignments && !assigning && (
                <Tooltip text="Grants a role of this realm's own catalog. It takes effect at this principal's next token.">
                  <button
                    type="button"
                    onClick={() => setAssigning(true)}
                    className="text-xs font-medium text-[#001E2B] hover:underline"
                  >
                    Assign a role
                  </button>
                </Tooltip>
              )}
            </div>

            {assigning && (
              <RoleAssigner
                busy={roleBusy !== null}
                catalog={roleCatalog}
                held={new Set((assignments ?? []).filter((a) => a.live).map((a) => a.roleId))}
                onCancel={() => setAssigning(false)}
                onAssign={(roleId) => void assignRole(roleId)}
              />
            )}

            {assignmentsError && <p className="mt-3 text-xs text-red-700">{assignmentsError}</p>}

            {assignments && (
              assignments.length === 0
                ? <p className="mt-3 text-sm text-gray-400">This principal holds no role.</p>
                : (
                  <ul className="mt-3 space-y-2">
                    {assignments.map((assignment) => (
                      <li
                        key={assignment.roleId}
                        className={`flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm ${
                          assignment.live ? 'border-gray-200' : 'border-gray-100 bg-gray-50 text-gray-400'
                        }`}
                      >
                        <div className="min-w-0">
                          <span className="font-medium">{roleName(assignment.roleId)}</span>
                          <span className="ml-2 text-xs text-gray-400">
                            {assignment.live ? `since ${when(assignment.grantedAt)}` : 'lapsed'}
                            {assignment.expiresAt ? ` · until ${when(assignment.expiresAt)}` : ''}
                          </span>
                        </div>
                        {mayManageAssignments && assignment.live && (
                          <Tooltip text="Takes effect at this principal's next token. Everyone else holding this role is unaffected.">
                            <button
                              type="button"
                              disabled={roleBusy === assignment.roleId}
                              onClick={() => void revokeRole(assignment.roleId)}
                              aria-label={`Revoke ${assignment.roleId}`}
                              className="shrink-0 rounded-md border border-red-200 p-1.5 text-red-700 hover:bg-red-50 disabled:opacity-50"
                            >
                              <Trash2 size={13} />
                            </button>
                          </Tooltip>
                        )}
                      </li>
                    ))}
                  </ul>
                )
            )}
          </section>

          {!retired && <PasswordReset id={id} />}
          <CredentialsHeld id={id} />
          <AuthorizedApplications id={id} />

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
                <Tooltip text="Edit the name, email, external id and user name. Nothing here changes what this principal may do.">
                  <button
                    type="button"
                    onClick={() => setEditing(true)}
                    disabled={retired}
                    className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#023430] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50 disabled:border-gray-300 disabled:bg-gray-100 disabled:text-gray-400"
                  >
                    <Pencil size={12} aria-hidden />
                    Edit principal
                  </button>
                </Tooltip>
                <Tooltip text={user.active
                  ? 'Every token already issued stops working immediately, not at its expiry.'
                  : 'Restores access. Existing role assignments are unchanged; nothing has to be re-granted.'}
                >
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
                </Tooltip>
                <Tooltip text="Retires the record rather than deleting it, so the audit trail still resolves. Every token stops working at once.">
                  <button
                    type="button"
                    disabled={busy || retired}
                    onClick={() => void deprovision()}
                    className="inline-flex items-center gap-1.5 rounded-md border border-red-200 px-3 py-2 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 disabled:opacity-50"
                  >
                    <UserMinus size={12} aria-hidden />
                    Deprovision
                  </button>
                </Tooltip>
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

/** A picker over the realm's own role catalog, so assigning one never invents a role by hand. */
function RoleAssigner({ catalog, held, busy, onCancel, onAssign }: {
  catalog: RoleSummary[];
  held: Set<string>;
  busy: boolean;
  onCancel: () => void;
  onAssign: (roleId: string) => void;
}) {
  const available = catalog.filter((role) => !held.has(role.roleId));
  const [roleId, setRoleId] = useState(available[0]?.roleId ?? '');

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); if (roleId) onAssign(roleId); }}
      className="mt-3 flex flex-wrap items-end gap-2 rounded-lg border border-gray-200 bg-gray-50 p-3"
    >
      <label className="block">
        <span className="text-[10px] uppercase tracking-wider text-gray-400">Role</span>
        <select
          value={roleId}
          onChange={(event) => setRoleId(event.target.value)}
          className="mt-1 block h-[34px] min-w-[220px] rounded-lg border border-gray-200 px-2 text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
        >
          {available.length === 0
            ? <option value="">Every defined role is already held</option>
            : available.map((role) => <option key={role.roleId} value={role.roleId}>{role.displayName}</option>)}
        </select>
      </label>
      <button
        type="submit"
        disabled={busy || !roleId}
        className="h-[34px] rounded-md bg-[#001E2B] px-3 text-xs font-medium text-[#00ED64] hover:bg-[#023430] disabled:opacity-50"
      >
        {busy ? 'Assigning…' : 'Assign'}
      </button>
      <button
        type="button"
        onClick={onCancel}
        className="h-[34px] rounded-md border border-gray-300 px-3 text-xs font-medium text-gray-700 hover:bg-white"
      >
        Cancel
      </button>
    </form>
  );
}

/**
 * An administrator setting a new password directly, without knowing the current one.
 *
 * The v43 replacement for LeafyPay's old "forced password reset". The value is never shown back:
 * once submitted, the form clears itself and only the outcome remains on screen.
 *
 * Shows the same live checklist the self-service change shows, from the same policy read from the
 * authority: an administrator setting a password is checked against the identical rules, so being
 * shown a different set of them here would be the console describing one policy two ways.
 */
function PasswordReset({ id }: { id: string }) {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);

  useEffect(() => {
    if (!open) return;
    let live = true;
    // Unreadable policy leaves the checklist with only what this form knows, never a guess.
    void loadPasswordPolicy().catch(() => null).then((read) => { if (live) setPolicy(read); });
    return () => { live = false; };
  }, [open]);

  // No current password on this path: an administrator does not hold it, which is the whole point
  // of the administrative reset, so there is no "differs from the current one" rule to show.
  const rules = evaluatePassword(policy, password, { confirmation: confirm });
  const satisfied = allMet(rules);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!satisfied) { setFailure('Some of the requirements above are not met yet.'); return; }
    setBusy(true);
    setFailure(null);
    try {
      await callApi(`/identities/${encodeURIComponent(id)}/credentials/password`, {
        method: 'POST',
        body: { password },
        subject: 'that password',
      });
      setPassword('');
      setConfirm('');
      setDone(true);
      setOpen(false);
    } catch (failureValue) {
      setFailure(failureValue instanceof ApiError ? failureValue.message : 'That password could not be set.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
          <KeyRound size={14} className="text-gray-400" aria-hidden />
          Password
        </h2>
        {!open && (
          <Tooltip text="Sets the password directly, without knowing the current one. Checked against the same policy self-registration enforces, and never shown back once set.">
            <button type="button" onClick={() => { setOpen(true); setDone(false); }} className="text-xs font-medium text-[#001E2B] hover:underline">
              Set a new password
            </button>
          </Tooltip>
        )}
      </div>

      {done && !open && <p className="mt-2 text-xs text-gray-500">The password was changed. It is not shown here.</p>}

      {open && (
        <form onSubmit={submit} className="mt-3 grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">New password</span>
            <input
              type="password"
              required
              minLength={policy?.minLength ?? 8}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Confirm</span>
            <input
              type="password"
              required
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>

          <PasswordRules rules={rules} className="sm:col-span-2" />

          {failure && <p className="text-xs text-red-700 sm:col-span-2">{failure}</p>}

          <div className="flex items-center gap-2 sm:col-span-2">
            <button
              type="submit"
              disabled={busy || !satisfied}
              className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] hover:bg-[#023430] disabled:opacity-50"
            >
              {busy ? 'Setting…' : 'Set password'}
            </button>
            <button
              type="button"
              onClick={() => { setOpen(false); setPassword(''); setConfirm(''); setFailure(null); }}
              className="rounded-md border border-gray-300 px-3 py-2 text-xs font-medium text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </section>
  );
}

interface HeldCredential {
  credentialId: string;
  type: string;
  label?: string;
  clientId?: string;
  clientName?: string;
  status: string;
  createdAt: string;
  lastUsedAt?: string;
}

const CREDENTIAL_TYPE_LABEL: Record<string, string> = {
  password: 'Password',
  public_key: 'Authenticator',
  oauth_client: 'Application',
  client_secret: 'Client secret',
  totp: 'One-time code',
  recovery_code: 'Recovery code',
  api_key: 'API key',
};

/**
 * Every credential this principal holds, one type discriminated collection read whole (ADR-001: an
 * OAuth application is a `credential` too, not a separate registry).
 *
 * Retiring is offered only for an authenticator. An application is withdrawn from its own
 * registration screen, which already does the extra work a withdrawal needs; a password is replaced
 * by a reset, not revoked. Both are linked to rather than reimplemented here.
 */
function CredentialsHeld({ id }: { id: string }) {
  const confirm = useConfirm();
  const [credentials, setCredentials] = useState<HeldCredential[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const body = await callApi<{ credentials: HeldCredential[] }>(
        `/identities/${encodeURIComponent(id)}/credentials`,
        { subject: 'this principal\'s credentials' },
      );
      setCredentials(body.credentials);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'This principal\'s credentials could not be read.');
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function retire(credential: HeldCredential) {
    if (!(await confirm(`Retire "${credential.label ?? credential.credentialId}"? It stops working immediately.`))) return;
    setBusy(credential.credentialId);
    try {
      await callApi(`/identities/${encodeURIComponent(id)}/credentials/${encodeURIComponent(credential.credentialId)}`, {
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

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
        <KeyRound size={14} className="text-gray-400" aria-hidden />
        Credentials held
      </h2>
      <p className="mt-1 text-sm text-gray-500">
        Every way this principal can be authenticated, passwords, authenticators and registered
        applications alike, in one place.
      </p>

      {error && <p className="mt-3 text-xs text-red-700">{error}</p>}

      {!credentials
        ? <p className="mt-3 text-sm text-gray-400">Reading…</p>
        : credentials.length === 0
          ? <p className="mt-3 text-sm text-gray-400">No credential recorded for this principal.</p>
          : (
            <ul className="mt-3 space-y-2">
              {credentials.map((credential) => (
                <li
                  key={credential.credentialId}
                  className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm ${
                    credential.status === 'active' ? 'border-gray-200' : 'border-gray-100 bg-gray-50 text-gray-400'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">
                        {credential.clientName || credential.label || CREDENTIAL_TYPE_LABEL[credential.type] || credential.type}
                      </span>
                      <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-500">
                        {CREDENTIAL_TYPE_LABEL[credential.type] ?? credential.type}
                      </span>
                      <StatusBadge status={credential.status} />
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">
                      {credential.type === 'oauth_client' && credential.clientId
                        ? (
                          <Link href={`/system/credentials/applications/${encodeURIComponent(credential.clientId)}`} className="hover:underline">
                            open the registration
                          </Link>
                        )
                        : `since ${when(credential.createdAt)}`}
                      {credential.lastUsedAt && ` · last used ${when(credential.lastUsedAt)}`}
                    </p>
                  </div>
                  {credential.type === 'public_key' && credential.status === 'active' && (
                    <button
                      type="button"
                      disabled={busy === credential.credentialId}
                      onClick={() => void retire(credential)}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-50"
                    >
                      <Trash2 size={12} aria-hidden />
                      Retire
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
    </section>
  );
}

interface OversightGrant {
  grantId: string;
  clientId: string;
  clientName: string;
  status: 'active' | 'revoked';
  grantedAt: string;
  revokedAt?: string;
}

/**
 * Applications this principal has authorized, the oversight side of the self-service view at
 * `/system/applications`.
 *
 * Withdrawing is offered; restoring one is not, because giving access back without the person
 * approving it again is theirs alone to do, the same asymmetry the API itself enforces.
 */
function AuthorizedApplications({ id }: { id: string }) {
  const confirm = useConfirm();
  const [grants, setGrants] = useState<OversightGrant[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const body = await callApi<{ grants: OversightGrant[] }>('/grants', {
        query: { subjectId: id, status: 'all' },
        subject: 'what this principal has authorized',
      });
      setGrants(body.grants);
      setError(null);
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'What this principal has authorized could not be read.');
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function revoke(grant: OversightGrant) {
    if (!(await confirm(`Withdraw ${grant.clientName || grant.clientId}'s authorization? It stops acting for this principal immediately.`))) return;
    setBusy(grant.grantId);
    try {
      await callApi(`/grants/${encodeURIComponent(grant.grantId)}`, {
        method: 'DELETE',
        query: { subjectId: id },
        subject: 'that authorization',
      });
      await load();
    } catch (failure) {
      setError(failure instanceof ApiError ? failure.message : 'That authorization could not be withdrawn.');
    } finally {
      setBusy(null);
    }
  }

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600">
        <Layers size={14} className="text-gray-400" aria-hidden />
        Authorized applications
      </h2>
      <p className="mt-1 text-sm text-gray-500">
        What this principal has allowed to act on their behalf. Restoring a withdrawn one is not
        offered here: giving access back without the person approving it again is theirs alone to do.
      </p>

      {error && <p className="mt-3 text-xs text-red-700">{error}</p>}

      {!grants
        ? <p className="mt-3 text-sm text-gray-400">Reading…</p>
        : grants.length === 0
          ? <p className="mt-3 text-sm text-gray-400">This principal has authorized nothing yet.</p>
          : (
            <ul className="mt-3 space-y-2">
              {grants.map((grant) => (
                <li
                  key={grant.grantId}
                  className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm ${
                    grant.status === 'active' ? 'border-gray-200' : 'border-gray-100 bg-gray-50 text-gray-400'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/system/credentials/applications/${encodeURIComponent(grant.clientId)}`}
                        className="font-medium text-[#001E2B] hover:underline"
                      >
                        {grant.clientName || grant.clientId}
                      </Link>
                      <StatusBadge status={grant.status} />
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">
                      Authorized {when(grant.grantedAt)}
                      {grant.revokedAt && ` · withdrawn ${when(grant.revokedAt)}`}
                    </p>
                  </div>
                  {grant.status === 'active' && (
                    <button
                      type="button"
                      disabled={busy === grant.grantId}
                      onClick={() => void revoke(grant)}
                      className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-red-200 px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-50 disabled:opacity-50"
                    >
                      <ShieldOff size={12} aria-hidden />
                      Withdraw
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
    </section>
  );
}
