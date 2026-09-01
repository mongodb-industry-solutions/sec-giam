'use client';

import { Check, ShieldCheck, X } from 'lucide-react';
import type { ConsentPrompt } from '../lib/authorizationRequest';

/**
 * Asking the person whether an application may have their identity.
 *
 * The identities belong to this authority, so every application that wants one is asking for
 * something that is not its own, and the answer is this person's to give. Shown once per client and
 * per set of scopes: a client that later widens what it asks for is asking a new question.
 *
 * What each scope MEANS is spelled out rather than printed as its wire name. A screen that lists
 * `read:accounts` and asks for agreement has obtained a click, not consent, which is the failure the
 * whole page exists to avoid.
 */

const SCOPE_LABELS: Record<string, string> = {
  openid: 'Confirm who you are',
  profile: 'Read your name and profile details',
  email: 'Read your email address',
  'read:accounts': 'See your accounts and their balances',
  'read:transactions': 'See your transaction history',
  'read:beneficiaries': 'See the payees you have saved',
  'write:beneficiaries': 'Add and remove saved payees',
  'write:transfers': 'Start transfers from your accounts',
  'read:rtp': 'See requests to pay addressed to you',
  'write:rtp': 'Send requests to pay on your behalf',
};

export function ConsentPanel({
  prompt, onApprove, onDeny, busy,
}: {
  prompt: ConsentPrompt;
  onApprove: () => void;
  onDeny: () => void;
  busy?: boolean;
}) {
  return (
    <main className="flex min-h-screen items-center justify-center p-4 sm:p-8">
      <div className="w-full max-w-md rounded-xl border bg-white p-8 shadow-sm">
        <div className="text-center">
          {prompt.logoUri
            ? <img src={prompt.logoUri} alt="" className="mx-auto h-12 w-12 rounded-lg object-contain" />
            : <ShieldCheck className="mx-auto text-mongodb-dark" size={40} />}
          <h1 className="mt-3 text-xl font-semibold text-mongodb-dark">
            {prompt.clientName} wants to sign you in
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            It is asking to use your identity here. Nothing is shared until you agree.
          </p>
        </div>

        <ul className="mt-6 space-y-2">
          {prompt.scopes.map((scope) => (
            <li key={scope} className="flex items-start gap-2 text-sm text-gray-700">
              <Check size={15} className="mt-0.5 shrink-0 text-mongodb-green" />
              <span>
                {SCOPE_LABELS[scope] ?? scope}
                {/* The wire name stays visible for anything without a plain-language label, so an
                    unlabelled scope is obvious rather than silently vague. */}
                {!SCOPE_LABELS[scope] && <span className="ml-1 text-xs text-gray-400">(raw scope)</span>}
              </span>
            </li>
          ))}
        </ul>

        <div className="mt-7 flex gap-3">
          <button
            type="button"
            onClick={onDeny}
            disabled={busy}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border px-4 py-2.5 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-50 disabled:opacity-40"
          >
            <X size={15} />
            Not now
          </button>
          <button
            type="button"
            onClick={onApprove}
            disabled={busy}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-lg bg-mongodb-dark px-4 py-2.5 text-sm font-semibold text-mongodb-green transition-colors hover:opacity-90 disabled:opacity-40"
          >
            <Check size={15} />
            {busy ? 'Authorising...' : 'Allow'}
          </button>
        </div>

        <p className="mt-4 text-center text-xs text-gray-400">
          You can withdraw this at any time from your applications list.
        </p>
      </div>
    </main>
  );
}
