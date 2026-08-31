'use client';

import { apiUrl } from './env';
import { storedToken } from './session';

/**
 * The console's access to the administrative API.
 *
 * The credential is held in this browser and sent per request. It is never written into a cookie,
 * because a cookie would be attached to every call the browser makes to this origin, including ones
 * the console did not initiate.
 *
 * The console builds itself from the catalog rather than from a hardcoded list of screens, so a view
 * added at the authority appears here with no frontend change. A console that has to be edited in
 * step with the API is one that will eventually disagree with it.
 */

const TOKEN_KEY = 'giam.admin.token';

export function adminToken(): string {
  return typeof window === 'undefined' ? '' : window.sessionStorage.getItem(TOKEN_KEY) ?? '';
}

export function setAdminToken(token: string): void {
  // Session storage, not local: closing the tab ends it. An operator credential that outlives the
  // session it was typed into is one nobody remembers is still there.
  window.sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearAdminToken(): void {
  window.sessionStorage.removeItem(TOKEN_KEY);
}

/**
 * What to present to the administrative surface: the SIGNED-IN person first.
 *
 * The console used to accept only the operator credential, so a manager who had already signed in was
 * asked for a shared password to look at the realm they administer, and the act stopped having a name
 * against it. The surface authorises by role now, so the person's own token is the better credential
 * and is preferred. The operator token remains for break-glass, which is what it is for.
 */
function presentedToken(): string {
  return storedToken() || adminToken();
}

export class AdminError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string): Promise<T> {
  const response = await fetch(apiUrl(path), {
    headers: { authorization: `Bearer ${presentedToken()}` },
    cache: 'no-store',
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new AdminError(response.status, body.detail ?? body.title ?? `The request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export interface ConsoleView {
  name: string;
  summary: string;
  note?: string;
  realmScoped: boolean;
  fields: string[];
}

export interface ViewPage {
  records: Array<Record<string, unknown>>;
  total: number;
}

export function listViews(): Promise<{ views: ConsoleView[] }> {
  return request('/admin/views');
}

export function readView(
  view: string,
  options: { realm?: string; q?: string; limit?: number; skip?: number } = {},
): Promise<ViewPage> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(options)) {
    if (value !== undefined && value !== '') query.set(key, String(value));
  }
  const suffix = query.toString();
  return request(`/admin/views/${encodeURIComponent(view)}${suffix ? `?${suffix}` : ''}`);
}

export interface Posture {
  status: string;
  findings?: Array<{ code: string; risk?: string; remedy?: string; detail?: string }>;
}

export function readPosture(): Promise<Posture> {
  return request('/admin/posture');
}

/** Renders a value without pretending a nested object is a string. */
export function cellText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value);
}
