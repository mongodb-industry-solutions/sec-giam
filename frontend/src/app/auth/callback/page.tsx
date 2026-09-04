'use client';

import { useEffect, useState } from 'react';
import { completeConsoleAuthorization } from '../../../lib/session';
import { AuthBackdrop } from '../../../components/AuthBackdrop';

/**
 * Where the authority sends the browser back with the console's own authorization code.
 *
 * This page did not exist before v41 P4, and it could not have: the console used to POST to the
 * authorization endpoint and read the code out of a JSON response, so nothing ever navigated here
 * and the registered redirect URI was a value nobody visited. With a conforming endpoint the code
 * arrives the ordinary way, in the query string of a redirect, and something has to be here to
 * receive it.
 *
 * It shows almost nothing on purpose. The person has already signed in; this is the last hop of a
 * flow they should not have to think about, so it says what it is doing and leaves.
 */
export default function CallbackPage() {
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const error = params.get('error');
    const code = params.get('code');

    /**
     * An error arrives here as `error` and `error_description`, because that is how a conforming
     * authorization server reports one. Shown rather than swallowed: this is the console's own
     * flow, so there is no relying party to hand the explanation to.
     */
    if (error) {
      setFailure(params.get('error_description') || error);
      return;
    }
    if (!code) {
      setFailure('The authority returned no authorization code.');
      return;
    }

    completeConsoleAuthorization(code).then((token) => {
      // The person is signed in either way: the session is a cookie and a record, and the token is
      // only what the console needs to read its own screens. So a failure here goes to the console
      // rather than back to sign-in, and the screens that need a token say so themselves.
      window.location.replace(token ? '/system' : '/system?token=unavailable');
    });
  }, []);

  return (
    <AuthBackdrop>
      <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
        {failure ? (
          <>
            <h1 className="text-xl font-semibold text-mongodb-dark">That did not complete</h1>
            <p className="mt-2 text-sm text-gray-600">{failure}</p>
            <a href="/auth/login" className="mt-6 inline-block text-sm underline">Try signing in again</a>
          </>
        ) : (
          <>
            <h1 className="text-xl font-semibold text-mongodb-dark">Signing you in…</h1>
            <p className="mt-2 text-sm text-gray-500">Exchanging the authorization code.</p>
          </>
        )}
      </div>
    </AuthBackdrop>
  );
}
