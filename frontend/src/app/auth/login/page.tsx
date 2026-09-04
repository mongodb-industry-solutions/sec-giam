'use client';

import { useEffect, useState } from 'react';
import { SignInPanel, type SignedIn } from '../../../components/SignInPanel';
import {
  readPendingAuthorization, continueAuthorization, type PendingAuthorization,
} from '../../../lib/authorizationRequest';
import { AuthBackdrop } from '../../../components/AuthBackdrop';

/**
 * Signing in, and continuing an authorization the authority parked here.
 *
 * Much simpler since v41 P4, because this page stopped being a participant in the protocol. It used
 * to hold the whole authorization request in its URL, POST it to the authorization endpoint, receive
 * either a code or a consent prompt in JSON, hold the session so it could repeat the request with a
 * consent flag, and redirect the browser itself. Consent lives on its own page now, and the request
 * lives in the authority.
 *
 * What is left is the job this page should always have had: take a credential, and send the browser
 * back where it came from.
 */
export default function LoginPage() {
  const [signedIn, setSignedIn] = useState<SignedIn | null>(null);
  const [pending, setPending] = useState<PendingAuthorization | null>(null);
  const [realm, setRealm] = useState<string | null>(null);
  const [returning, setReturning] = useState(false);

  useEffect(() => {
    const search = window.location.search;
    setPending(readPendingAuthorization(search));
    // The authority names the realm when it sends somebody here. Guessing it from a client id would
    // work until two realms registered the same one.
    setRealm(new URLSearchParams(search).get('realm') ?? 'leafypay');
  }, []);

  function handleSignedIn(result: SignedIn) {
    /**
     * Straight back to the authorization endpoint, which now has a session cookie to read.
     *
     * Whether that produces a code, a consent screen or an error for the application is the
     * authority's decision, and this page learns it by being replaced. Deciding here is what the
     * previous version did, and it is why consent could be asserted by whoever built the request.
     */
    if (pending) {
      setReturning(true);
      continueAuthorization(pending);
      return;
    }
    setSignedIn(result);
  }

  if (returning) {
    return (
      <AuthBackdrop>
        <p className="text-sm text-gray-300">Returning you to the application…</p>
      </AuthBackdrop>
    );
  }

  if (signedIn) {
    return (
      <AuthBackdrop>
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-2xl font-semibold text-mongodb-dark">Signed in</h1>
          <p className="mt-2 text-gray-600">{signedIn.displayName ?? signedIn.userName}</p>
          <div className="mt-6 flex justify-center gap-4 text-sm">
            <a href="/system" className="underline">Your console</a>
            <a href="/profile/credentials" className="underline">Your authenticators</a>
            <a href="/auth/logout" className="underline">Sign out</a>
          </div>
        </div>
      </AuthBackdrop>
    );
  }

  // Held until the realm is known: the panel reads its roster on mount, and starting on the wrong
  // directory would show the wrong people and then quietly correct itself.
  if (realm === null) {
    return <AuthBackdrop><p className="text-sm text-gray-300">Loading…</p></AuthBackdrop>;
  }

  return (
    <AuthBackdrop>
      <SignInPanel
        defaultRealm={realm}
        onSignedIn={handleSignedIn}
      />
    </AuthBackdrop>
  );
}
