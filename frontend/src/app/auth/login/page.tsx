'use client';

import { useEffect, useState } from 'react';
import { SignInPanel, type SignedIn } from '../../../components/SignInPanel';
import {
  readAuthorizationRequest, completeAuthorization, denyAuthorization,
  type AuthorizationRequest, type ConsentPrompt,
} from '../../../lib/authorizationRequest';
import { ConsentPanel } from '../../../components/ConsentPanel';
import { AuthBackdrop } from '../../../components/AuthBackdrop';

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
  // The consent question, and the session that will answer it. Both are held because approving
  // repeats the same authorization request, and the session is not in the URL.
  const [consent, setConsent] = useState<ConsentPrompt | null>(null);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);

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
      const asked = await completeAuthorization(result.realm, result.sessionId, request);
      // A prompt means the browser stayed here: this person has not authorised this application
      // before, and nothing is handed over until they say so.
      if (asked) {
        setSessionId(result.sessionId);
        setConsent(asked);
        setReturning(false);
      }
      return;
    }
    setSignedIn(result);
  }

  async function handleApprove() {
    if (!request || !sessionId) return;
    setApproving(true);
    const asked = await completeAuthorization(realm ?? 'leafypay', sessionId, request, { consentGranted: true });
    // Approving and still being asked would loop the screen, so it is reported rather than repeated.
    if (asked) setApproving(false);
  }

  if (consent && request) {
    return (
      <ConsentPanel
        prompt={consent}
        busy={approving}
        onApprove={handleApprove}
        onDeny={() => denyAuthorization(request)}
      />
    );
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
        {...(request?.clientId ? { clientId: request.clientId } : {})}
        onSignedIn={handleSignedIn}
      />
    </AuthBackdrop>
  );
}
