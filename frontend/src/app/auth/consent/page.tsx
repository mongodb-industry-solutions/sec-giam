'use client';

import { useCallback, useEffect, useState } from 'react';
import { ConsentPanel } from '../../../components/ConsentPanel';
import { AuthBackdrop } from '../../../components/AuthBackdrop';
import { LoadingState } from '../../../components/ResultState';
import { API_PREFIX, apiUrl } from '../../../lib/env';
import type { ConsentPrompt } from '../../../lib/authorizationRequest';

/**
 * The consent screen, reached by a redirect from the authorization endpoint.
 *
 * Its own page since v41 P4, and that is the point rather than a tidy-up. Consent used to be a
 * boolean the CALLER put in the authorization request (`consent_granted: true`), on an endpoint
 * declared with no security, with a comment saying a client should never set it and nothing
 * preventing one. Any party that could reach the endpoint could approve on somebody's behalf.
 *
 * Now the authority sends the browser here with nothing but a `request_id`, this page ASKS what that
 * request is for, and the answer is assembled from the stored request. So what the person reads is
 * what will be exercised, and neither this page nor whoever built the URL can change it. The
 * decision posts back with the session cookie, which is what makes it the person's own.
 */
export default function ConsentPage() {
  const [prompt, setPrompt] = useState<ConsentPrompt | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [context, setContext] = useState<{ realm: string; requestId: string } | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const realm = params.get('realm');
    const requestId = params.get('request_id');
    if (!realm || !requestId) {
      setFailure('This page was opened without an authorization request.');
      return;
    }
    setContext({ realm, requestId });

    fetch(apiUrl(`${API_PREFIX}/realms/${realm}/protocol/oidc/auth/consent?request_id=${encodeURIComponent(requestId)}`), {
      // The session cookie is the whole point, so it has to be sent. Without this the browser omits
      // it on a cross-origin request and the authority correctly answers that nobody is signed in.
      credentials: 'include',
    })
      .then(async (response) => {
        if (!response.ok) {
          const body = await response.json().catch(() => ({})) as { error_description?: string };
          setFailure(body.error_description ?? 'That authorization request is no longer available.');
          return;
        }
        setPrompt(await response.json() as ConsentPrompt);
      })
      .catch(() => setFailure('The authority could not be reached.'));
  }, []);

  const decide = useCallback(async (approved: boolean, grantedScopes?: string[]) => {
    if (!context) return;
    setBusy(true);
    try {
      const response = await fetch(apiUrl(`${API_PREFIX}/realms/${context.realm}/protocol/oidc/auth/consent`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          request_id: context.requestId,
          approved,
          // Only what was ticked. The authority intersects it with what was asked, so a
          // decision can narrow and never widen.
          ...(grantedScopes ? { granted_scopes: grantedScopes } : {}),
        }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({})) as { error_description?: string };
        setFailure(body.error_description ?? 'That decision could not be recorded.');
        setBusy(false);
        return;
      }
      // The authority says where to go next, which is itself when approved and the application's
      // redirect URI when declined. Deciding that here would put the flow's shape in two places.
      const { continue: next } = await response.json() as { continue: string };
      window.location.assign(next);
    } catch {
      setFailure('The authority could not be reached.');
      setBusy(false);
    }
  }, [context]);

  if (failure) {
    return (
      <AuthBackdrop>
        <div className="w-full max-w-md rounded-xl border bg-white p-8 text-center shadow-sm">
          <h1 className="text-xl font-semibold text-mongodb-dark">Nothing to approve</h1>
          <p className="mt-2 text-sm text-gray-600">{failure}</p>
          <a href="/auth/login" className="mt-6 inline-block text-sm underline">Back to sign in</a>
        </div>
      </AuthBackdrop>
    );
  }

  if (!prompt) {
    return <AuthBackdrop><LoadingState label="Reading what is being asked for…" /></AuthBackdrop>;
  }

  return (
    <ConsentPanel
      prompt={prompt}
      busy={busy}
      onApprove={(granted) => decide(true, granted)}
      onDeny={() => decide(false)}
    />
  );
}
