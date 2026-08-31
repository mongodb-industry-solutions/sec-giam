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

/**
 * Exchanges the established session for a code and returns the browser to the application.
 *
 * A refusal goes back to the application as an OAuth error rather than being shown here: the relying
 * party is the one that can explain it in its own terms, and stranding the person on the authority
 * with a message about a client they never chose is the failure this whole path exists to avoid.
 */
export async function completeAuthorization(
  realm: string,
  sessionId: string,
  request: AuthorizationRequest,
): Promise<void> {
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
      }),
    });
  } catch {
    window.location.assign(withParams(request.redirectUri, {
      error: 'temporarily_unavailable',
      error_description: 'The authority could not be reached.',
      state: request.state,
    }));
    return;
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { title?: string; detail?: string };
    window.location.assign(withParams(request.redirectUri, {
      // An unregistered redirect is the one case never echoed to the caller, but the authority already
      // refuses that before answering, so anything reaching here is a request it recognised.
      error: 'access_denied',
      error_description: body.detail ?? body.title ?? 'The authorization request was refused.',
      state: request.state,
    }));
    return;
  }

  const { code, state } = await response.json() as { code: string; state?: string };
  window.location.assign(withParams(request.redirectUri, { code, state: state ?? request.state }));
}
