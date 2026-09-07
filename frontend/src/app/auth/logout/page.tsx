'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { apiUrl } from '../../../lib/env';
import { storedToken, storedSessionId, clearSession } from '../../../lib/session';
import { AuthBackdrop } from '../../../components/AuthBackdrop';

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
    // A relying party's return address, validated server-side against its own registration.
    const postLogoutRedirectUri = params.get('post_logout_redirect_uri') ?? undefined;
    clearSession();

    // Called regardless of whether this tab remembers a session id: a relying party's sign-in never
    // gives it one, the session lives only in the cookie this fetch carries.
    fetch(apiUrl(`/realms/${DEFAULT_REALM}/protocol/openid-connect/logout`), {
      method: 'POST',
      credentials: 'include',
      headers: {
        'content-type': 'application/json',
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        ...(sessionId ? { session_id: sessionId } : {}),
        ...(postLogoutRedirectUri ? { post_logout_redirect_uri: postLogoutRedirectUri } : {}),
      }),
    })
      .then(async (response) => {
        // The validated response, not the raw query string, is what this page trusts.
        const body = await response.json().catch(() => ({})) as { post_logout_redirect_uri?: string };
        window.location.replace(body.post_logout_redirect_uri ?? safeReturn(params.get('redirect')));
      })
      .catch(() => setFailed(true));
  }, [params]);

  return (
    <AuthBackdrop>
      <div className="text-center">
        <p className="text-sm text-gray-200">{failed ? 'Signed out of this browser.' : 'Signing you out…'}</p>
        {failed && (
          // Honest about what did not happen. Telling somebody they are signed out everywhere when
          // they may not be is the one thing this page must never do.
          <p className="mx-auto mt-3 max-w-sm text-xs text-gray-400">
            The identity service could not be reached, so other applications may still hold a session.
            Sign out again when it is back.
          </p>
        )}
      </div>
    </AuthBackdrop>
  );
}

export default function LogoutPage() {
  return (
    <Suspense fallback={
      <AuthBackdrop>
        <p className="text-sm text-gray-300">Signing you out…</p>
      </AuthBackdrop>
    }>
      <LogoutInner />
    </Suspense>
  );
}
