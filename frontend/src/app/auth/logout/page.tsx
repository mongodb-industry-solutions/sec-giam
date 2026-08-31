'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { apiUrl } from '../../../lib/env';
import { storedToken, storedSessionId, clearSession } from '../../../lib/session';

/**
 * Signing out, everywhere.
 *
 * Ending the session here ends it for every application holding a token from it: the authority
 * notifies them, and it raises the principal's session epoch so anything it did not record is
 * retired too. That is the capability the platform did not have while each application kept its own
 * session, where signing out of one left the others open.
 *
 * The local session is cleared first and unconditionally. If the call fails, the person is still
 * signed out of this browser, which is the part they can see and the part they asked for.
 */

const DEFAULT_REALM = 'leafypay';

function safeReturn(raw: string | null): string {
  if (!raw) return '/auth/login';
  // A same-origin path only. An absolute URL here would make this an open redirect, and a sign-out
  // page is a particularly attractive one because people arrive at it already trusting it.
  return /^\/(?![/\\])/.test(raw) ? raw : '/auth/login';
}

function LogoutInner() {
  const params = useSearchParams();
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const sessionId = storedSessionId();
    const token = storedToken();
    clearSession();

    const done = () => window.location.replace(safeReturn(params.get('redirect')));

    if (!sessionId) {
      done();
      return;
    }

    fetch(apiUrl(`/realms/${DEFAULT_REALM}/protocol/openid-connect/logout`), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ sessionId }),
    })
      .then(done)
      .catch(() => setFailed(true));
  }, [params]);

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <p className="text-sm text-gray-500">{failed ? 'Signed out of this browser.' : 'Signing you out…'}</p>
        {failed && (
          // Honest about what did not happen. Telling somebody they are signed out everywhere when
          // they may not be is the one thing this page must never do.
          <p className="mx-auto mt-3 max-w-sm text-xs text-gray-500">
            The identity service could not be reached, so other applications may still hold a session.
            Sign out again when it is back.
          </p>
        )}
      </div>
    </main>
  );
}

export default function LogoutPage() {
  return (
    <Suspense fallback={
      <main className="min-h-screen flex items-center justify-center bg-gray-50">
        <p className="text-sm text-gray-500">Signing you out…</p>
      </main>
    }>
      <LogoutInner />
    </Suspense>
  );
}
