'use client';

import { apiUrl } from './env';
import { storedRealm, storedToken } from './session';

/**
 * What the console knows about the signed-in principal, and how it talks to the authority.
 *
 * Claims are read here only to decide what to RENDER. Every decision that matters is made by the API
 * against the same token, and it checks the signature. A screen that a claim would hide is still
 * refused by the API when somebody types the address, which is the order these two checks belong in.
 */

export interface Permission {
  resource: string;
  action: string;
}

export interface Claims {
  sub: string;
  preferred_username?: string;
  name?: string;
  email?: string;
  roles?: string[];
  scope?: string;
  permissions?: Permission[];
  exp?: number;
  iss?: string;
  aud?: string | string[];
}

export function decodeClaims(token: string): Claims | null {
  const segments = token.split('.');
  if (segments.length !== 3) return null;
  try {
    return JSON.parse(atob(segments[1].replace(/-/g, '+').replace(/_/g, '/'))) as Claims;
  } catch {
    return null;
  }
}

/** The claims of the token currently held, or null when nobody is signed in. */
export function currentClaims(): Claims | null {
  const token = storedToken();
  return token ? decodeClaims(token) : null;
}

export function isExpired(claims: Claims): boolean {
  return typeof claims.exp === 'number' && claims.exp * 1000 <= Date.now();
}

export function displayName(claims: Claims): string {
  return claims.name || claims.preferred_username || claims.sub;
}

export function initials(claims: Claims): string {
  const source = displayName(claims).trim();
  const parts = source.split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

/** Whether the claims carry a named permission. Absent claims mean no, never "probably". */
export function can(claims: Claims | null, resource: string, action: string): boolean {
  if (!claims) return false;
  return (claims.permissions ?? []).some((p) => p.resource === resource && p.action === action);
}

// Offered only when the claims say the person administers identity, so the console never advertises
// a surface that would refuse them.
export function administersIdentity(claims: Claims | null): boolean {
  if (!claims) return false;
  if ((claims.roles ?? []).some((role) => /admin|auditor|security/i.test(role))) return true;
  return (claims.permissions ?? []).some((p) => /realm|client|identit|role|polic|key|session|audit/i.test(p.resource));
}

/** A failure a screen can print as it is, rather than a stack trace or a bare status code. */
export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

function messageFor(status: number, detail: string, subject: string): string {
  if (status === 401) return 'That session is not valid any more. Sign in again.';
  if (status === 403) return `Your roles do not allow reading ${subject}.`;
  if (status === 404) return `${subject} could not be found.`;
  if (status >= 500) return `The identity service failed while reading ${subject}.`;
  return detail || `${subject} could not be loaded.`;
}

interface CallOptions {
  method?: string;
  body?: unknown;
  /** Plain-language name of what is being read, used to build the error message. */
  subject?: string;
  query?: Record<string, string | number | undefined>;
}

/**
 * One call to the authority, addressed to the realm the person signed into.
 *
 * Path is written without the realm prefix so no caller has to remember to add it, and so a page
 * cannot accidentally read a realm the person is not in.
 */
export async function callApi<T>(path: string, options: CallOptions = {}): Promise<T> {
  const token = storedToken();
  const subject = options.subject ?? 'that record';
  if (!token) throw new ApiError(401, 'Sign in to see this.');

  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined && value !== '') search.set(key, String(value));
  }
  const suffix = search.toString() ? `?${search}` : '';

  let response: Response;
  try {
    response = await fetch(apiUrl(`/realms/${encodeURIComponent(storedRealm())}${path}${suffix}`), {
      method: options.method ?? 'GET',
      headers: {
        authorization: `Bearer ${token}`,
        ...(options.body ? { 'content-type': 'application/json' } : {}),
      },
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
      cache: 'no-store',
    });
  } catch {
    throw new ApiError(0, 'The identity service could not be reached.');
  }

  if (!response.ok) {
    const problem = await response.json().catch(() => null) as { detail?: string; title?: string } | null;
    throw new ApiError(response.status, messageFor(response.status, problem?.detail ?? problem?.title ?? '', subject));
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

/** Formats a timestamp for reading, and says so plainly when there is not one. */
export function when(value?: string | null): string {
  if (!value) return 'never';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toLocaleString();
}

export function startOfToday(): string {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
}
