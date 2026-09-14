'use client';

import { apiUrlObject } from './env';

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

/**
 * Form prefill the authority passed along, from `login_hint` and `prefill_password`.
 *
 * Separate from `PendingAuthorization` on purpose. What is authorized is read back from the ticket
 * by the authority and nothing here can influence it; these two values only decide what the fields
 * start out holding, so a person walking a demo does not retype a credential they were handed.
 */
export interface SignInPrefill {
  login?: string;
  password?: string;
}

/** The prefill in the current URL, if the authority sent any. */
export function readSignInPrefill(search: string): SignInPrefill {
  const params = new URLSearchParams(search);
  return {
    ...(params.get('login_hint') ? { login: params.get('login_hint') as string } : {}),
    ...(params.get('prefill_password') ? { password: params.get('prefill_password') as string } : {}),
  };
}

/** One scope, as the authority describes it. The description is the deployment's, not this app's. */
export interface ConsentScope {
  name: string;
  /** Absent when the resource server that accepts this scope has not described it. */
  description?: string;
  /** Declining it ends the flow rather than narrowing it, so the screen cannot untick it. */
  required?: boolean;
  /** Held from an earlier authorisation, so the person is being asked to confirm rather than grant. */
  alreadyGranted?: boolean;
}

/**
 * What the person is being asked to agree to. Assembled by the authority from the stored request.
 *
 * No authority name here: the screen shows GIAM's own brand for that half, the same fixed identity
 * on every realm, not a per-realm value carried over the wire. A realm like `LeafyIdp` is a trust
 * boundary shared by a group of applications, and the application asking is one of them; which one
 * is asking is what a person is agreeing to, and the realm it happens to answer to is not.
 */
export interface ConsentPrompt {
  clientName: string;
  clientUri?: string;
  logoUri?: string;
  scopes: ConsentScope[];
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
  const url = apiUrlObject(`/realms/${pending.realm}/protocol/openid-connect/auth`);
  url.searchParams.set('request_id', pending.requestId);
  window.location.assign(url.toString());
}
