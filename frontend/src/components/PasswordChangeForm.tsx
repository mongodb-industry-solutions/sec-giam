'use client';

import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import { Tooltip } from './Tooltip';
import { ApiError, callApi } from '../lib/console';

/**
 * A person changing their own password.
 *
 * The self-service counterpart of the administrator's `PasswordReset` on the identity detail page
 * (`/system/identities/[id]`): same shape, same policy, but this one asks for the CURRENT password
 * instead of an authority permission, because proving it is what stands in for one. Neither value is
 * ever shown back; once submitted, the form clears itself and only the outcome remains on screen.
 */
export function PasswordChangeForm() {
  const [open, setOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  function reset() {
    setCurrentPassword('');
    setNewPassword('');
    setConfirm('');
    setFailure(null);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (newPassword !== confirm) { setFailure('The new password and its confirmation do not match.'); return; }
    if (newPassword === currentPassword) { setFailure('The new password must differ from the current one.'); return; }

    setBusy(true);
    setFailure(null);
    try {
      await callApi('/credentials/password', {
        method: 'POST',
        body: { currentPassword, newPassword, newPasswordConfirmation: confirm },
        subject: 'your password',
      });
      reset();
      setDone(true);
      setOpen(false);
    } catch (failureValue) {
      // A 403 here means the current password did not match, not a missing role: `callApi`'s
      // generic mapping reads every 403 as an authority refusal, which would be the wrong sentence
      // for a proof-of-possession failure over the caller's OWN credential.
      setFailure(
        failureValue instanceof ApiError && failureValue.status === 403
          ? 'That is not your current password.'
          : failureValue instanceof ApiError ? failureValue.message : 'Your password could not be changed.',
      );
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
          <Tooltip text="Requires the current password: proving it is what stands in for an administrator's permission. Checked against the same policy self-registration enforces, and never shown back once set.">
            <button type="button" onClick={() => { setOpen(true); setDone(false); }} className="text-xs font-medium text-[#001E2B] hover:underline">
              Change your password
            </button>
          </Tooltip>
        )}
      </div>

      {done && !open && <p className="mt-2 text-xs text-gray-500">Your password was changed. It is not shown here.</p>}

      {open && (
        <form onSubmit={submit} className="mt-3 grid gap-3 sm:grid-cols-2">
          <label className="block sm:col-span-2">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Current password</span>
            <input
              type="password"
              required
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">New password</span>
            <input
              type="password"
              required
              minLength={8}
              autoComplete="new-password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Confirm new password</span>
            <input
              type="password"
              required
              autoComplete="new-password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              className="mt-1 block w-full rounded-lg border border-gray-200 px-2.5 py-2 text-sm text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
          </label>

          {failure && <p className="text-xs text-red-700 sm:col-span-2">{failure}</p>}

          <div className="flex items-center gap-2 sm:col-span-2">
            <button
              type="submit"
              disabled={busy || newPassword.length < 8 || currentPassword.length === 0}
              className="rounded-md bg-[#001E2B] px-3 py-2 text-xs font-medium text-[#00ED64] hover:bg-[#023430] disabled:opacity-50"
            >
              {busy ? 'Changing…' : 'Change password'}
            </button>
            <button
              type="button"
              onClick={() => { setOpen(false); reset(); }}
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
