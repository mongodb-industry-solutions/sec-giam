'use client';

import { useEffect, useState } from 'react';
import { Bug, Eye, EyeOff } from 'lucide-react';
import { apiUrl } from '../lib/env';
import { tokenFromSession } from '../lib/session';
import { BRAND } from '../config/brand';
import { Tooltip } from './Tooltip';

/**
 * THE sign-in form for the whole platform.
 *
 * Every application redirects here, so this is the only screen on which a credential is ever typed.
 * One component rather than one per application: a second copy would be a second place for the
 * roster, the directory picker and the error handling to drift, and the point of moving identity out
 * was to have one.
 */

interface Provider {
  name: string;
  displayName: string;
  protocol: string;
  enabled: boolean;
  notice?: string;
}

export interface RosterEntry {
  subjectId: string;
  userName: string;
  email?: string;
  role?: string;
}

export interface LoginContext {
  realm: string;
  displayName: string;
  notice?: string;
  registrationEnabled: boolean;
  branding: { displayName: string; logoUri?: string; primaryColor?: string };
  providers: Provider[];
  roster: RosterEntry[];
}

export interface SignedIn {
  userName?: string;
  sessionId: string;
  realm: string;
}

// Plaintext behind the seed fixture's credential hashes, so it belongs to the demo data.
const DEMO_PASSWORD = 'demo-password';

/** Personas grouped by the role they hold, so the picker offers a ready-made user per role. */
function byRole(roster: RosterEntry[]): Array<[string, RosterEntry[]]> {
  const groups = new Map<string, RosterEntry[]>();
  for (const entry of roster) {
    const role = entry.role ?? 'no role assigned';
    const existing = groups.get(role);
    if (existing) existing.push(entry);
    else groups.set(role, [entry]);
  }
  return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
}

export function SignInPanel({
  defaultRealm = 'leafypay',
  heading,
  clientId,
  onSignedIn,
}: {
  defaultRealm?: string;
  heading?: string;
  /** Narrows the demo roster to the personas this application should offer. */
  clientId?: string;
  onSignedIn?: (signedIn: SignedIn) => void;
}) {
  const [context, setContext] = useState<LoginContext | null>(null);
  const [realm, setRealm] = useState(defaultRealm);
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [debugMode, setDebugMode] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(apiUrl(`/realms/${realm}/login-context${clientId ? `?client_id=${encodeURIComponent(clientId)}` : ''}`))
      .then((response) => (response.ok ? response.json() : null))
      .then((data) => { if (!cancelled) setContext(data); })
      .catch(() => { if (!cancelled) setContext(null); });
    return () => { cancelled = true; };
  }, [realm, clientId]);

  async function submit(credentials: { login: string; password: string }) {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(apiUrl(`/realms/${realm}/login`), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      if (!response.ok) {
        // One message for every failure. Distinguishing an unknown principal from a wrong password is
        // an enumeration oracle, and the person signing in cannot act on the difference anyway.
        setError('That did not work. Check the details and try again.');
        return;
      }
      const body = await response.json();
      // A token for the console itself, obtained the ordinary way. Failing here does not undo the
      // sign-in: the person IS signed in, and only the screens needing a token are affected.
      await tokenFromSession(realm, body.sessionId);
      onSignedIn?.({ userName: body.userName, sessionId: body.sessionId, realm });
    } catch {
      setError('The identity service could not be reached.');
    } finally {
      setBusy(false);
    }
  }

  function pick(entry: RosterEntry) {
    setLogin(entry.userName);
    setPassword(DEMO_PASSWORD);
    setError(null);
  }

  const grouped = context ? byRole(context.roster) : [];

  return (
    <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl sm:p-8">
      <div className="relative mb-6 text-center">
        <Tooltip text={debugMode
          ? 'Debug mode is on: a ready-made user is offered for each role so you can sign in with one click. Click to turn it off.'
          : 'Turn on debug mode. It offers a ready-made user for each role, so you can sign in with one click instead of typing credentials.'}>
          <button
            type="button"
            onClick={() => setDebugMode(!debugMode)}
            aria-label={debugMode ? 'Disable debug mode' : 'Enable debug mode'}
            className={`absolute right-0 top-0 rounded-lg p-1.5 transition-colors ${
              debugMode
                ? 'bg-amber-100 text-amber-600 hover:bg-amber-200'
                : 'text-gray-300 hover:bg-gray-100 hover:text-gray-500'
            }`}
          >
            <Bug size={14} />
          </button>
        </Tooltip>

        <div className="mb-2 text-4xl">
          <img src="/app-icon.png" alt={`${BRAND.full} Icon`} className="mx-auto h-20 w-20" />
        </div>
        <h1 className="text-2xl font-bold text-[#001E2B]">
          {heading ?? context?.branding.displayName ?? context?.displayName ?? BRAND.full}
        </h1>
        <p className="mt-1 text-sm text-gray-500">Application Mode: Sign In</p>
      </div>

      <form
        onSubmit={(event) => { event.preventDefault(); submit({ login, password }); }}
        className="space-y-4"
      >
        <div>
          <label className="mb-1 flex items-center gap-1 text-sm font-medium text-gray-700" htmlFor="realm-picker">
            Authentication Domain
            <Tooltip text="The domain decides how you are signed in and who manages the accounts. Pick the one your account belongs to." />
          </label>
          {context === null ? (
            <div className="w-full animate-pulse rounded-lg border bg-gray-50 px-3 py-2 text-sm text-gray-600">
              Loading domains…
            </div>
          ) : (
            <select
              id="realm-picker"
              value={realm}
              onChange={(event) => { setRealm(event.target.value); setLogin(''); setPassword(''); setError(null); }}
              className="w-full rounded-lg border bg-white px-3 py-2 text-sm"
            >
              <option value={context.realm}>{context.displayName}</option>
              {context.providers.map((provider) => (
                <option key={provider.name} value={context.realm} disabled={!provider.enabled}>
                  {provider.displayName}
                  {provider.enabled ? '' : ' (not active in this build)'}
                </option>
              ))}
            </select>
          )}
        </div>

        {debugMode && grouped.length > 0 && (
          <div>
            <label className="mb-1 flex items-center gap-1 text-sm font-medium text-gray-700" htmlFor="persona-picker">
              Select User
              <Tooltip text="Ready-made accounts, grouped by role, so you can see the platform through different eyes. Pick one and its credentials are filled in for you." />
            </label>
            <select
              id="persona-picker"
              value={login}
              onChange={(event) => {
                const entry = context?.roster.find((candidate) => candidate.userName === event.target.value);
                if (entry) pick(entry);
              }}
              className="w-full rounded-lg border px-3 py-2 text-sm"
            >
              <option value="">Select a user…</option>
              {grouped.map(([role, entries]) => (
                <optgroup key={role} label={role}>
                  {entries.map((entry) => (
                    <option key={entry.subjectId} value={entry.userName}>{entry.userName}</option>
                  ))}
                </optgroup>
              ))}
            </select>
          </div>
        )}

        <div>
          <label className="mb-1 flex items-center gap-1 text-sm font-medium text-gray-700" htmlFor="login">
            Email or user name
            <Tooltip text={<>
              What identifies your account.
              {' '}Short on time? Turn on debug mode
              {' '}<Bug size={11} className="mx-0.5 inline align-[-1px] text-amber-400" />
              {' '}and pick a ready-made user for any role instead of typing credentials.
            </>} />
          </label>
          <input
            id="login"
            value={login}
            onChange={(event) => { setLogin(event.target.value); setError(null); }}
            autoComplete="username"
            placeholder="user@example.com"
            className="w-full rounded-lg border px-3 py-2 text-sm"
          />
        </div>

        <div>
          <label className="mb-1 flex items-center gap-1 text-sm font-medium text-gray-700" htmlFor="password">
            Password
            <Tooltip text="Your secret. Never share it with anyone." />
          </label>
          <div className="relative">
            <input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              placeholder={debugMode ? 'Auto-filled on user selection' : 'Enter password'}
              className="w-full rounded-lg border px-3 py-2 pr-10 text-sm"
            />
            <button
              type="button"
              onClick={() => setShowPassword((visible) => !visible)}
              tabIndex={-1}
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-600 transition-colors hover:text-gray-600"
            >
              {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={!login || !password || busy}
          className="w-full rounded-lg bg-[#001E2B] py-2.5 font-semibold text-[#00ED64] transition-colors hover:bg-[#00ED64] hover:text-[#001E2B] disabled:opacity-40"
        >
          {busy ? 'Signing in…' : 'Sign In'}
        </button>
      </form>

      {context?.registrationEnabled && (
        <p className="mt-3 text-center text-xs text-gray-500">
          Don&apos;t have an account?{' '}
          <a href={`/auth/register?realm=${encodeURIComponent(realm)}`} className="font-semibold text-[#001E2B] underline hover:text-[#00684A]">
            Register
          </a>
        </p>
      )}

      <p className="mt-4 text-center text-xs text-gray-600">
        {debugMode && grouped.length > 0
          ? 'Select a user to fill in their credentials. Every preloaded account shares the same password.'
          : 'Enter the credentials managed by the selected domain.'}
      </p>

      {context?.notice && <p className="mt-3 text-center text-xs text-gray-500">{context.notice}</p>}
    </div>
  );
}
