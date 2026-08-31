'use client';

import { useEffect, useState } from 'react';
import { apiUrl } from '../../../lib/env';

/**
 * Self-service sign-up, where the realm offers it.
 *
 * The form does not decide whether registration is available: it asks the realm and renders what it
 * is told. A console that shows a sign-up form the authority will refuse teaches people that the
 * product is broken, which is worse than not offering the form at all.
 */

const DEFAULT_REALM = 'leafypay';

export default function RegisterPage() {
  const [realm] = useState(DEFAULT_REALM);
  const [offered, setOffered] = useState<boolean | null>(null);
  const [branding, setBranding] = useState<{ displayName?: string; primaryColor?: string }>({});
  const [form, setForm] = useState({ formattedName: '', userName: '', email: '', password: '', confirm: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<'active' | 'pending' | null>(null);

  useEffect(() => {
    fetch(apiUrl(`/realms/${realm}/login-context`))
      .then((response) => (response.ok ? response.json() : null))
      .then((context) => {
        setOffered(Boolean(context?.registrationEnabled));
        setBranding(context?.branding ?? {});
      })
      .catch(() => setOffered(false));
  }, [realm]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (form.password !== form.confirm) {
      setError('The two passwords do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(apiUrl(`/realms/${realm}/register`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          userName: form.userName,
          password: form.password,
          ...(form.email ? { email: form.email } : {}),
          ...(form.formattedName ? { formattedName: form.formattedName } : {}),
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(body.detail ?? body.title ?? 'That did not work. Check the details and try again.');
        return;
      }
      setOutcome(body.status === 'active' ? 'active' : 'pending');
    } catch {
      setError('The identity service could not be reached.');
    } finally {
      setBusy(false);
    }
  }

  const accent = branding.primaryColor ?? '#00ED64';

  if (offered === false) {
    return (
      <main className="min-h-screen flex items-center justify-center p-8">
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-xl font-semibold text-mongodb-dark">Registration is closed</h1>
          <p className="mt-2 text-sm text-gray-600">
            Accounts here are created for you rather than requested. Speak to whoever administers this
            directory.
          </p>
        </div>
      </main>
    );
  }

  if (outcome) {
    return (
      <main className="min-h-screen flex items-center justify-center p-8">
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-xl font-semibold text-mongodb-dark">
            {outcome === 'active' ? 'Your account is ready' : 'Your request was received'}
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            {outcome === 'active'
              ? 'You can sign in now.'
              : 'This directory reviews new accounts before they can sign in. Yours exists and is waiting for that review.'}
          </p>
          <a href="/auth/login" className="mt-6 inline-block text-sm underline">Go to sign in</a>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen flex items-center justify-center p-8">
      <form onSubmit={submit} className="w-full max-w-md rounded-xl border bg-white p-8 shadow-sm">
        <h1 className="text-2xl font-semibold text-mongodb-dark">
          {branding.displayName ? `Join ${branding.displayName}` : 'Create an account'}
        </h1>

        <div className="mt-6 space-y-4">
          {([
            ['formattedName', 'Full name', 'text', 'name'],
            ['userName', 'User name', 'text', 'username'],
            ['email', 'Email', 'email', 'email'],
            ['password', 'Password', 'password', 'new-password'],
            ['confirm', 'Confirm password', 'password', 'new-password'],
          ] as const).map(([field, label, type, autoComplete]) => (
            <div key={field}>
              <label className="mb-1 block text-xs font-medium text-gray-500" htmlFor={field}>{label}</label>
              <input
                id={field}
                type={type}
                autoComplete={autoComplete}
                value={form[field]}
                onChange={(event) => setForm({ ...form, [field]: event.target.value })}
                className="w-full rounded-md border px-3 py-2"
              />
            </div>
          ))}
        </div>

        {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

        <button
          type="submit"
          disabled={busy || offered === null}
          style={{ backgroundColor: accent }}
          className="mt-6 w-full rounded-md px-4 py-2 font-medium text-mongodb-dark disabled:opacity-50"
        >
          {busy ? 'Creating…' : 'Create account'}
        </button>

        <p className="mt-4 text-center text-xs text-gray-500">
          Already have an account? <a href="/auth/login" className="underline">Sign in</a>
        </p>
      </form>
    </main>
  );
}
