'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { CredentialsPanel } from '../../../components/CredentialsPanel';
import { PasswordChangeForm } from '../../../components/PasswordChangeForm';
import { storedToken } from '../../../lib/session';

/**
 * The standalone address for a person's authenticators, kept because relying parties link to it.
 *
 * The console renders the same panel inside its shell. This page is the same capability without one,
 * for somebody who arrived here directly rather than through the console.
 */
export default function CredentialsPage() {
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => { setToken(storedToken()); }, []);

  if (token === null) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-gray-50 p-8 text-sm text-gray-500">
        Checking your session…
      </main>
    );
  }

  if (!token) {
    return (
      <main className="flex min-h-screen items-center justify-center p-8">
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-xl font-semibold text-mongodb-dark">Sign in first</h1>
          <p className="mt-2 text-sm text-gray-600">
            These are your own authenticators, so this page needs to know who you are.
          </p>
          <Link href="/auth/login" className="mt-6 inline-block text-sm underline">Go to sign in</Link>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-gray-50 p-4 sm:p-8">
      <div className="mx-auto max-w-2xl space-y-5">
        <div>
          <h1 className="text-2xl font-semibold text-mongodb-dark">Your credentials</h1>
          <p className="mt-2 text-sm text-gray-600">
            Your password, and the devices that can approve a sign-in for you. Only the public half of
            each device key is ever stored here, so the authenticator list cannot be used to sign in
            as you.
          </p>
        </div>

        <PasswordChangeForm />
        <CredentialsPanel />

        <Link href="/system" className="inline-block text-xs text-gray-500 hover:text-mongodb-dark">
          Go to the console
        </Link>
      </div>
    </main>
  );
}
