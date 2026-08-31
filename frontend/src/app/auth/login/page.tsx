'use client';

import { useEffect, useState } from 'react';
import { SignInPanel, type SignedIn } from '../../../components/SignInPanel';
import { readAuthorizationRequest, completeAuthorization, type AuthorizationRequest } from '../../../lib/authorizationRequest';

/**
 * The sign-in screen every application redirects to.
 *
 * It renders the REALM's branding rather than this console's, which is how the page a relying party's
 * user sees is visually that relying party's page without this console becoming that application.
 * The alternative, letting each application collect the credential, is precisely what the extraction
 * exists to stop.
 *
 * When an authorization request is present in the URL, signing in produces a code and the browser
 * goes back to the application. Without one, somebody opened this page directly.
 */
export default function LoginPage() {
  const [signedIn, setSignedIn] = useState<SignedIn | null>(null);
  const [request, setRequest] = useState<AuthorizationRequest | null>(null);
  const [realm, setRealm] = useState<string | null>(null);
  const [returning, setReturning] = useState(false);

  useEffect(() => {
    const search = window.location.search;
    setRequest(readAuthorizationRequest(search));
    // The application names its directory. Guessing it from the client id would work until two realms
    // registered the same one.
    setRealm(new URLSearchParams(search).get('realm') ?? 'leafypay');
  }, []);

  async function handleSignedIn(result: SignedIn) {
    if (request) {
      setReturning(true);
      await completeAuthorization(result.realm, result.sessionId, request);
      return;
    }
    setSignedIn(result);
  }

  if (returning) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4 sm:p-8 text-sm text-gray-500">
        Returning you to the application…
      </main>
    );
  }

  if (signedIn) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-2xl font-semibold text-mongodb-dark">Signed in</h1>
          <p className="mt-2 text-gray-600">{signedIn.userName}</p>
          <div className="mt-6 flex justify-center gap-4 text-sm">
            <a href="/system" className="underline">Your console</a>
            <a href="/profile/credentials" className="underline">Your authenticators</a>
            <a href="/auth/logout" className="underline">Sign out</a>
          </div>
        </div>
      </main>
    );
  }

  // Held until the realm is known: the panel reads its roster on mount, and starting on the wrong
  // directory would show the wrong people and then quietly correct itself.
  if (realm === null) {
    return <main className="flex min-h-screen items-center justify-center p-4 sm:p-8 text-sm text-gray-500">Loading…</main>;
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-4 sm:p-8">
      <SignInPanel
        defaultRealm={realm}
        {...(request?.clientId ? { clientId: request.clientId } : {})}
        onSignedIn={handleSignedIn}
      />
    </main>
  );
}
