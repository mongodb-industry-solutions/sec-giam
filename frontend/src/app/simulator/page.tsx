'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import {
  Store, QrCode, FileJson, BookOpen, LogIn, ArrowRight, ExternalLink, Home, LayoutDashboard, X,
} from 'lucide-react';
import {
  RELYING_PARTY_PUBLIC_URL, demoPublicUrl, DISCOVERY_URL, API_DOC_URL, SIMULATOR_REALM,
} from '../../lib/constants';
import { QrCodePanel } from '../../components/QrCodePanel';

/**
 * Simulator Mode: the entry point that picks which part of the identity story to walk.
 *
 * Every card here reaches something that already exists. The step-by-step drivers for the remaining
 * flows are listed further down as what they are, not built yet, rather than dressed as cards that
 * lead nowhere.
 */

interface HubCard {
  key: string;
  title: string;
  description: string;
  icon: typeof LogIn;
  cta: string;
  onSelect: () => void;
  // Set when the card cannot act in this environment, which is how a missing address is surfaced
  // instead of becoming a link that fails.
  unavailable?: string;
  // Set when the card leaves this app. Those destinations have no way back, so they open in a new
  // tab and the card says so.
  external?: boolean;
}

/**
 * Opens a destination that is NOT part of this app.
 *
 * `noopener` is not decoration: without it the opened page can reach back through `window.opener`
 * and navigate this one.
 */
function openExternal(target: string) {
  window.open(target, '_blank', 'noopener,noreferrer');
}

const PENDING_FLOWS = [
  ['Backchannel authentication', 'A decoupled sign-in approved on a second device, with the pending request visible while it waits.'],
  ['Delegation', 'One principal acting for another, with the acting party preserved in the token rather than replaced.'],
  ['Token exchange', 'A token swapped for one scoped to a different audience.'],
  ['Single logout', 'One sign-out ending the session everywhere it was used.'],
];

export default function SimulatorPage() {
  const router = useRouter();
  const [shareTarget, setShareTarget] = useState<string | null>(null);

  const cards: HubCard[] = [
    {
      key: 'relying-party',
      title: 'Relying party app',
      description:
        'Open a registered application (a merchant storefront) that holds no password of its own. Signing in '
        + 'there is the authorization code flow with PKCE: the browser is redirected here, the credential is '
        + 'typed only here, and the application gets back a code it exchanges for a token.',
      icon: Store,
      cta: 'Open the application',
      external: true,
      onSelect: () => openExternal(RELYING_PARTY_PUBLIC_URL),
      unavailable: RELYING_PARTY_PUBLIC_URL
        ? undefined
        : 'This environment publishes no relying party. Set NEXT_PUBLIC_GIAM_URL_RELYING_PARTY to reach one.',
    },
    {
      key: 'share',
      title: 'Share with QR code',
      description:
        'Show a QR code with this environment\'s address so anyone can open the demo on a phone and follow '
        + 'along, or approve a sign-in from a second device.',
      icon: QrCode,
      cta: 'Show QR code',
      onSelect: () => setShareTarget(demoPublicUrl('/simulator')),
    },
    {
      key: 'sign-in',
      title: 'Sign in to the authority',
      description:
        'Sign in on the authority itself and see the session, the claims and the permissions that come out of '
        + 'it, according to the role the account holds.',
      icon: LogIn,
      cta: 'Go to sign-in',
      onSelect: () => router.push('/system'),
    },
    {
      key: 'discovery',
      title: 'Discovery document',
      description:
        `The metadata for the ${SIMULATOR_REALM} realm: the endpoints, the grant types, the signing keys and the `
        + 'scopes, published where the standard says a client should look for them.',
      icon: FileJson,
      cta: 'Open discovery',
      external: true,
      onSelect: () => openExternal(DISCOVERY_URL),
    },
    {
      key: 'api',
      title: 'API reference',
      description:
        'The authority\'s own reference: authorization, token, introspection, userinfo, directory and the '
        + 'administrative surface behind them.',
      icon: BookOpen,
      cta: 'Open API reference',
      external: true,
      onSelect: () => openExternal(API_DOC_URL),
    },
  ];

  return (
    <div className="mx-auto mt-8 max-w-5xl pb-12">
      <div className="mb-10 text-center">
        <div className="mb-3 text-5xl">🎬</div>
        <h1 className="mb-2 text-2xl font-bold text-[#001E2B]">Simulator Mode</h1>
        <p className="mx-auto max-w-xl text-sm text-gray-600">
          Choose which part of the identity story you want to explore.
        </p>
      </div>

      <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map((c) => {
          const Icon = c.icon;
          return (
            <button
              key={c.key}
              onClick={c.onSelect}
              disabled={Boolean(c.unavailable)}
              title={c.unavailable}
              className="group flex flex-col rounded-xl border border-gray-200 bg-white p-6 text-left shadow-sm transition-all enabled:hover:-translate-y-0.5 enabled:hover:border-[#001E2B] enabled:hover:bg-[#001E2B] enabled:hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-60"
            >
              {/* On the dark hover state the icon chip inverts to green-on-dark for contrast. */}
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg bg-[#001E2B] text-[#00ED64] transition-colors group-hover:bg-[#00ED64] group-hover:text-[#001E2B]">
                <Icon size={22} />
              </div>
              <h2 className="mb-2 font-semibold text-[#001E2B] transition-colors group-hover:text-white">{c.title}</h2>
              <p className="flex-1 text-sm text-gray-500 transition-colors group-hover:text-gray-300">{c.description}</p>
              {c.unavailable && <span className="mt-4 text-xs text-amber-700">{c.unavailable}</span>}
              <span className={`mt-4 inline-flex items-center gap-1.5 text-sm font-semibold text-[#001E2B] transition-colors group-hover:text-[#00ED64] ${c.unavailable ? 'hidden' : ''}`}>
                {c.cta}
                {/* The icon says which kind of click this is: onward within the demo, or out to another site. */}
                {c.external
                  ? <ExternalLink size={14} aria-label="opens in a new tab" />
                  : <ArrowRight size={15} className="transition-transform group-hover:translate-x-0.5" />}
              </span>
            </button>
          );
        })}
      </div>

      <div className="mt-10 rounded-xl border border-gray-200 bg-white p-5">
        <h2 className="font-semibold text-[#001E2B]">Guided step by step, not built yet</h2>
        <p className="mt-1 text-sm text-gray-500">
          The authority already implements each of these, and each is covered by its own tests. What is
          missing is a screen driving them one request at a time.
        </p>
        <ul className="mt-4 space-y-3">
          {PENDING_FLOWS.map(([name, detail]) => (
            <li key={name} className="rounded-lg border border-gray-100 bg-gray-50 p-3">
              <p className="text-sm font-medium text-[#001E2B]">{name}</p>
              <p className="mt-0.5 text-sm text-gray-500">{detail}</p>
            </li>
          ))}
        </ul>
      </div>

      {shareTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" onClick={() => setShareTarget(null)}>
          <div className="w-full max-w-sm rounded-xl bg-white p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center justify-between">
              <h2 className="font-semibold text-[#001E2B]">Share this demo</h2>
              <button type="button" onClick={() => setShareTarget(null)} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600" aria-label="Close">
                <X size={16} />
              </button>
            </div>
            <QrCodePanel value={shareTarget} label="Scan to open the demo" />
          </div>
        </div>
      )}

      {/* Secondary navigation: leave the simulator or jump straight into Application mode. */}
      <div className="mt-8 flex flex-col items-center justify-center gap-3 border-t border-gray-200 pt-6 sm:flex-row">
        <Link
          href="/"
          className="group inline-flex items-center gap-2 rounded-lg border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-600 transition-colors hover:border-gray-400 hover:bg-gray-50"
        >
          <Home size={15} className="text-gray-400 transition-colors group-hover:text-gray-600" />
          Exit to main menu
        </Link>
        <Link
          href="/system"
          className="group inline-flex items-center gap-2 rounded-lg border border-[#001E2B] bg-white px-4 py-2 text-sm font-medium text-[#001E2B] transition-colors hover:bg-[#001E2B] hover:text-[#00ED64]"
        >
          <LayoutDashboard size={15} />
          Go to Application mode
          <ArrowRight size={14} className="transition-transform group-hover:translate-x-0.5" />
        </Link>
      </div>
    </div>
  );
}
