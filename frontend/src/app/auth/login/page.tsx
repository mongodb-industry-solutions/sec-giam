'use client';

import { useEffect, useState } from 'react';
import { SignInPanel, type SignedIn } from '../../../components/SignInPanel';
import {
  readPendingAuthorization, readSignInPrefill, continueAuthorization,
  type PendingAuthorization, type SignInPrefill,
} from '../../../lib/authorizationRequest';
import { AuthBackdrop } from '../../../components/AuthBackdrop';
import { readEntryDefaults, type EntryDefaults } from '../../../lib/entryParams';

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
  const [prefill, setPrefill] = useState<SignInPrefill>({});
  const [entry, setEntry] = useState<EntryDefaults>({});
  const [returning, setReturning] = useState(false);

  useEffect(() => {
    const search = window.location.search;
    setPending(readPendingAuthorization(search));
    // `login_hint`, and the demo's `prefill_password`, as the authority passed them on. Form prefill
    // only: what is authorized is the ticket's, so filling these cannot alter the request.
    setPrefill(readSignInPrefill(search));
    /**
     * The authority names the realm when it sends somebody here. Guessing it from a client id would
     * work until two realms registered the same one.
     *
     * The same URL may also name a DOMAIN, which opens the picker on one path instead of on the
     * realm's first enabled one. Presentation only: it cannot alter the authorization request, and
     * which domain a credential really belongs to is still resolved server side.
     */
    const defaults = readEntryDefaults(search);
    setEntry(defaults);
    setRealm(defaults.realm ?? 'LeafyIdp');
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
      // The navigation is started FIRST: if it cannot be, the throw reaches the panel, which reports
      // it, rather than this screen having already replaced the panel with a message that never ends.
      continueAuthorization(pending);
      setReturning(true);
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
        defaultDomain={entry.domain}
        requestId={pending?.requestId}
        prefill={prefill}
        onSignedIn={handleSignedIn}
      />
    </AuthBackdrop>
  );
}
