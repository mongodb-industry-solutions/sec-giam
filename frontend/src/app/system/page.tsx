'use client';

import { useEffect, useState } from 'react';
import { SignInPanel, type SignedIn } from '../../components/SignInPanel';
import { storedToken, clearSession, CONSOLE_CLIENT_ID } from '../../lib/session';
import { BRAND } from '../../config/brand';

/**
 * Application Mode: the authority used as a product, by a person who signed in.
 *
 * Distinct from the sign-in page, which exists for relying parties to redirect to, and from the
 * operator console, which holds an administrative credential rather than anybody's identity. What
 * this screen shows is what the SIGNED-IN principal can reach, chosen from their own claims.
 */

interface Claims {
  sub: string;
  preferred_username?: string;
  name?: string;
  roles?: string[];
  scope?: string;
  permissions?: Array<{ resource: string; action: string }>;
  exp?: number;
  iss?: string;
}

interface Card {
  label: string;
  description: string;
  href: string;
}

// Everyone gets these: they are about the person's own identity, which needs no privilege.
const OWN_IDENTITY: Card[] = [
  {
    label: 'Your authenticators',
    description: 'The keys enrolled against your account, and the ability to remove one.',
    href: '/profile/credentials',
  },
];

// Offered only when the claims say the person administers identity, so the screen never advertises a
// surface that would refuse them.
const OVERSIGHT: Card[] = [
  {
    label: 'Operator console',
    description: 'Realms, clients, identities, roles, keys, sessions and the audit trail.',
    href: '/admin',
  },
];

function decode(token: string): Claims | null {
  const segments = token.split('.');
  if (segments.length !== 3) return null;
  try {
    return JSON.parse(atob(segments[1].replace(/-/g, '+').replace(/_/g, '/'))) as Claims;
  } catch {
    return null;
  }
}

// Unverified, and only ever used to decide what to RENDER. Every decision that matters is made by the
// API against the same token, and it checks the signature.
function administersIdentity(claims: Claims): boolean {
  if ((claims.roles ?? []).some((role) => /admin|auditor|security/i.test(role))) return true;
  return (claims.permissions ?? []).some((permission) => /realm|client|identit|role|polic|key|session|audit/i.test(permission.resource));
}

export default function SystemPage() {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const token = storedToken();
    setClaims(token ? decode(token) : null);
    setChecked(true);
  }, []);

  function afterSignIn(_signedIn: SignedIn) {
    const token = storedToken();
    setClaims(token ? decode(token) : null);
  }

  if (!checked) {
    return <main className="flex min-h-screen items-center justify-center text-sm text-gray-500">Checking your session…</main>;
  }

  if (!claims) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4 sm:p-8">
        <SignInPanel heading={`${BRAND.full} console`} clientId={CONSOLE_CLIENT_ID} onSignedIn={afterSignIn} />
      </main>
    );
  }

  const who = claims.preferred_username ?? claims.name ?? claims.sub;
  const cards = [...OWN_IDENTITY, ...(administersIdentity(claims) ? OVERSIGHT : [])];

  return (
    <main className="mx-auto w-full max-w-4xl p-4 sm:p-6 lg:p-8">
      <div className="mb-8 flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h1 className="text-2xl font-semibold text-mongodb-dark">{who}</h1>
          <p className="mt-1 text-sm text-gray-500">
            {(claims.roles ?? []).join(', ') || 'no role assigned'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => { clearSession(); setClaims(null); }}
          className="rounded-md border px-3 py-1.5 text-sm hover:bg-gray-50"
        >
          Sign out
        </button>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {cards.map((card) => (
          <a
            key={card.href}
            href={card.href}
            className="rounded-xl border bg-white p-5 shadow-sm transition hover:border-gray-400"
          >
            <h2 className="font-medium text-mongodb-dark">{card.label}</h2>
            <p className="mt-1 text-sm text-gray-500">{card.description}</p>
          </a>
        ))}
      </div>

      {!administersIdentity(claims) && (
        <p className="mt-6 text-xs text-gray-500">
          Signed in as an ordinary principal, so the administrative surfaces are not offered here. They
          would refuse this token, and a console that lists what it cannot open is worse than one that
          does not.
        </p>
      )}

      <div className="mt-10 rounded-xl border bg-gray-50 p-5">
        <p className="text-xs font-medium uppercase tracking-wide text-gray-600">Your token</p>
        <dl className="mt-2 grid gap-1 text-sm text-gray-600 sm:grid-cols-2">
          <div><dt className="inline text-gray-600">subject </dt><dd className="inline">{claims.sub}</dd></div>
          <div><dt className="inline text-gray-600">issuer </dt><dd className="inline">{claims.iss ?? 'n/a'}</dd></div>
          <div><dt className="inline text-gray-600">scope </dt><dd className="inline">{claims.scope ?? 'n/a'}</dd></div>
          <div>
            <dt className="inline text-gray-600">expires </dt>
            <dd className="inline">{claims.exp ? new Date(claims.exp * 1000).toLocaleTimeString() : 'n/a'}</dd>
          </div>
        </dl>
      </div>
    </main>
  );
}
