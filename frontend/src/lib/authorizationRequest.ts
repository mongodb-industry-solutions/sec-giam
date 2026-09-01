'use client';

import { apiUrl } from './env';

/**
 * Completing an authorization request that a relying party sent here.
 *
 * The applications redirect to this console's sign-in page carrying the ordinary OAuth parameters,
 * and until now the page ignored them: it signed the person in and left them standing on the
 * authority with no way back. Hosting the login is only half of the flow, and this is the other half.
 */

export interface AuthorizationRequest {
  clientId: string;
  redirectUri: string;
  responseType: string;
  scope?: string;
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}

/** The request in the current URL, or null when somebody simply opened the sign-in page. */
export function readAuthorizationRequest(search: string): AuthorizationRequest | null {
  const params = new URLSearchParams(search);
  const clientId = params.get('client_id');
  const redirectUri = params.get('redirect_uri');
  if (!clientId || !redirectUri) return null;
  return {
    clientId,
    redirectUri,
    responseType: params.get('response_type') ?? 'code',
    ...(params.get('scope') ? { scope: params.get('scope') as string } : {}),
    ...(params.get('state') ? { state: params.get('state') as string } : {}),
    ...(params.get('nonce') ? { nonce: params.get('nonce') as string } : {}),
    ...(params.get('code_challenge') ? { codeChallenge: params.get('code_challenge') as string } : {}),
    ...(params.get('code_challenge_method') ? { codeChallengeMethod: params.get('code_challenge_method') as string } : {}),
  };
}

function withParams(base: string, values: Record<string, string | undefined>): string {
  const url = new URL(base);
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined) url.searchParams.set(key, value);
  }
  return url.toString();
}

/** What the person is being asked to agree to, when they have not agreed to it before. */
export interface ConsentPrompt {
  clientName: string;
  clientUri?: string;
  logoUri?: string;
  scopes: string[];
}

/** Sends the browser back to the application saying the person declined. */
export function denyAuthorization(request: AuthorizationRequest): void {
  window.location.assign(withParams(request.redirectUri, {
    error: 'access_denied',
    error_description: 'The person declined to authorise this application.',
    state: request.state,
  }));
}

/**
 * Exchanges the established session for a code and returns the browser to the application.
 *
 * Returns a prompt instead when the person has not yet authorised this application: the identities
 * are this authority's, so handing one to an application is the person's decision and not a step to
 * pass through. Resolves to null in every other case, because the browser has already left.
 *
 * A refusal goes back to the application as an OAuth error rather than being shown here: the relying
 * party is the one that can explain it in its own terms, and stranding the person on the authority
 * with a message about a client they never chose is the failure this whole path exists to avoid.
 */
export async function completeAuthorization(
  realm: string,
  sessionId: string,
  request: AuthorizationRequest,
  options: { consentGranted?: boolean } = {},
): Promise<ConsentPrompt | null> {
  let response: Response;
  try {
    response = await fetch(apiUrl(`/realms/${realm}/protocol/openid-connect/auth`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_id: request.clientId,
        redirect_uri: request.redirectUri,
        response_type: request.responseType,
        session_id: sessionId,
        ...(request.scope ? { scope: request.scope } : {}),
        ...(request.state ? { state: request.state } : {}),
        ...(request.nonce ? { nonce: request.nonce } : {}),
        ...(request.codeChallenge ? { code_challenge: request.codeChallenge } : {}),
        ...(request.codeChallengeMethod ? { code_challenge_method: request.codeChallengeMethod } : {}),
        ...(options.consentGranted ? { consent_granted: true } : {}),
      }),
    });
  } catch {
    window.location.assign(withParams(request.redirectUri, {
      error: 'temporarily_unavailable',
      error_description: 'The authority could not be reached.',
      state: request.state,
    }));
    return null;
  }

  if (!response.ok) {
    // Two shapes reach here: the authorize endpoint answers with an OAuth error
    // (`error` / `error_description`), while a generic failure answers as a Problem
    // (`title` / `detail`). Reading only the Problem shape turned every refusal into the same
    // sentence, which cost a real diagnosis: "unknown client" and "scope not permitted" have
    // different fixes and were indistinguishable on screen.
    const body = await response.json().catch(() => ({})) as {
      title?: string; detail?: string; error?: string; error_description?: string;
    };
    window.location.assign(withParams(request.redirectUri, {
      // An unregistered redirect is the one case never echoed to the caller, but the authority already
      // refuses that before answering, so anything reaching here is a request it recognised.
      error: 'access_denied',
      error_description: body.error_description
        ?? body.detail
        ?? body.title
        ?? body.error
        ?? 'The authorization request was refused.',
      state: request.state,
    }));
    return null;
  }

  const body = await response.json() as {
    code?: string; state?: string;
    consent_required?: boolean; client_name?: string; client_uri?: string; logo_uri?: string;
    scopes?: string[];
  };

  if (body.consent_required) {
    return {
      clientName: body.client_name ?? request.clientId,
      ...(body.client_uri ? { clientUri: body.client_uri } : {}),
      ...(body.logo_uri ? { logoUri: body.logo_uri } : {}),
      scopes: body.scopes ?? [],
    };
  }

  // No code and no question is a shape neither side should be able to produce, so it is reported as
  // the authority's fault rather than redirected as the person's refusal.
  if (!body.code) {
    window.location.assign(withParams(request.redirectUri, {
      error: 'server_error',
      error_description: 'The authority returned neither a code nor a question.',
      state: request.state,
    }));
    return null;
  }

  window.location.assign(withParams(request.redirectUri, {
    code: body.code,
    state: body.state ?? request.state,
  }));
  return null;
}
