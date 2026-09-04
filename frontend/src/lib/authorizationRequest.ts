'use client';

import { apiUrl } from './env';

/**
 * Continuing an authorization request the authority sent this page.
 *
 * Almost all of this file went away in v41 P4, and what went away is the point. The console used to
 * hold the whole authorization request in its URL, POST it to the authorization endpoint as JSON,
 * read the code out of a JSON response, and redirect the browser itself. That made the console a
 * participant in a protocol it should only have been providing screens for, and it is why the
 * endpoint was not one a conforming client could drive.
 *
 * Now the authority owns the flow. It creates the pending request, sends the browser here with a
 * `request_id`, and this page's only job is to send it back once the person has signed in. The
 * parameters are never re-read from the URL on the way back, so nothing here can alter what was
 * asked for.
 */

/** A pending request this page was asked to help with, named by the authority. */
export interface PendingAuthorization {
  realm: string;
  requestId: string;
}

/** What the person is being asked to agree to. Assembled by the authority from the stored request. */
export interface ConsentPrompt {
  clientName: string;
  clientUri?: string;
  logoUri?: string;
  scopes: string[];
}

/**
 * The pending request in the current URL, or null when somebody simply opened the sign-in page.
 *
 * Two identifiers and nothing else. It used to read `client_id`, `redirect_uri`, `scope`, `state`,
 * `nonce` and the PKCE pair, because the page then had to send them onward; carrying them was
 * exactly what let a detour through sign-in alter the request that would be exercised.
 */
export function readPendingAuthorization(search: string): PendingAuthorization | null {
  const params = new URLSearchParams(search);
  const requestId = params.get('request_id');
  const realm = params.get('realm');
  if (!requestId || !realm) return null;
  return { realm, requestId };
}

/**
 * Sends the browser back to the authorization endpoint to continue.
 *
 * Does not return: the page is leaving. Whether the answer is a code, a consent screen or an error
 * for the application is the authority's to decide, and this page finds out by being replaced.
 */
export function continueAuthorization(pending: PendingAuthorization): void {
  const url = new URL(apiUrl(`/realms/${pending.realm}/protocol/openid-connect/auth`));
  url.searchParams.set('request_id', pending.requestId);
  window.location.assign(url.toString());
}
