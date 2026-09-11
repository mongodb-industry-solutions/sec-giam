'use client';

import { useState } from 'react';
import { AppWindow, Check, X } from 'lucide-react';
import type { ConsentPrompt } from '../lib/authorizationRequest';
import { AuthBackdrop } from './AuthBackdrop';
import { BRAND } from '../config/brand';

/**
 * Who is asking, and who is being asked to vouch: the application, then this authority, icon over
 * name for each, the same shape a federated sign-in uses to keep the two from being mistaken for
 * one another. The application did not get here on its own; it is the party in front, and the
 * authority is what a person is actually trusting to hand identity over.
 */
function PartyBadge({ logoUri, name }: { logoUri?: string; name: string }) {
  return (
    <div className="flex w-24 flex-col items-center gap-1.5">
      {logoUri ? (
        <img src={logoUri} alt={`${name} icon`} className="h-12 w-12 rounded-xl object-contain" />
      ) : (
        <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-gray-100 text-gray-400">
          <AppWindow size={22} aria-hidden />
        </span>
      )}
      <span className="max-w-full truncate text-xs font-medium text-gray-600" title={name}>{name}</span>
    </div>
  );
}

/**
 * A dashed connector rather than a solid one, deliberately: a solid arrow reads as data flowing
 * from the application to the authority, which is backwards. What is actually happening is the
 * authority admitting the application to its own SSO, so the line is drawn as a permission being
 * extended rather than a value being passed.
 */
function AuthorizationLink() {
  return (
    <svg width="36" height="14" viewBox="0 0 36 14" fill="none" aria-hidden className="mt-[-18px] shrink-0 text-gray-300">
      <line x1="1" y1="7" x2="26" y2="7" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3.5 3" strokeLinecap="round" />
      <path d="M25 2 L32 7 L25 12" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

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

/*
 * The scope label map lived here and is gone.
 *
 * It put a deployment's vocabulary ("See your accounts and their balances") in the CONSOLE, which
 * had two consequences. A person calling the authority directly could not learn what they were
 * agreeing to, because the meaning existed only in one screen. And two clients could describe the
 * same scope differently, since nothing made them agree.
 *
 * The descriptions come from the resource server that accepts each scope now, seeded as data. This
 * component renders what it is given and knows nothing about what a payment or an account is.
 */

export function ConsentPanel({
  prompt, onApprove, onDeny, busy,
}: {
  prompt: ConsentPrompt;
  /** Carries the scopes actually ticked, which may be fewer than were asked for. */
  onApprove: (grantedScopes: string[]) => void;
  onDeny: () => void;
  busy?: boolean;
}) {
  /**
   * What is currently ticked. Everything starts approved, and a required scope cannot be unticked.
   *
   * Starting from all-approved rather than none is deliberate: the common answer is yes to
   * everything, and a screen that makes the ordinary case the laborious one is a screen people click
   * through without reading. What matters is that saying no to ONE thing is possible at all, which
   * it was not before.
   */
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(prompt.scopes.map((scope) => scope.name)),
  );

  const toggle = (name: string, required: boolean) => {
    if (required) return;
    setSelected((held) => {
      const next = new Set(held);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  return (
    <AuthBackdrop>
      <div className="w-full max-w-md rounded-xl border bg-white p-8 shadow-sm">
        <div className="text-center">
          <div className="flex items-center justify-center gap-3">
            <PartyBadge logoUri={prompt.logoUri} name={prompt.clientName} />
            <AuthorizationLink />
            <PartyBadge logoUri="/app-icon.png" name={BRAND.full} />
          </div>
          <h1 className="mt-4 text-xl font-semibold text-mongodb-dark">
            {prompt.clientName} wants to sign you in
          </h1>
          <p className="mt-2 text-sm text-gray-600">
            It is asking {BRAND.full} to vouch for your identity. Nothing is shared until you agree.
          </p>
        </div>

        <ul className="mt-6 space-y-1.5">
          {prompt.scopes.map((scope) => (
            <li key={scope.name}>
              <label
                className={`flex items-start gap-2.5 rounded-lg border px-3 py-2.5 text-sm ${
                  scope.required ? 'border-gray-100 bg-gray-50 text-gray-500' : 'cursor-pointer border-gray-200 text-gray-700 hover:bg-gray-50'
                }`}
              >
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 shrink-0 accent-[#00684A]"
                  checked={selected.has(scope.name)}
                  disabled={scope.required}
                  onChange={() => toggle(scope.name, Boolean(scope.required))}
                />
                <span className="flex-1">
                  {/* The description comes from the authority. Without one the wire name is shown as
                      itself, so an undescribed scope is obviously vague rather than quietly so. */}
                  {scope.description ?? scope.name}
                  {!scope.description && <span className="ml-1 text-xs text-gray-400">(raw scope)</span>}
                  {scope.required && <span className="ml-1.5 text-xs text-gray-400">required</span>}
                  {scope.alreadyGranted && !scope.required && (
                    <span className="ml-1.5 text-xs text-gray-400">already allowed</span>
                  )}
                </span>
              </label>
            </li>
          ))}
        </ul>

        {selected.size < prompt.scopes.length && (
          <p className="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">
            {/* Said plainly, because a partly approved application failing later should not be a
                surprise the person has to work out for themselves. */}
            You are allowing part of what was asked for. The application may not work fully.
          </p>
        )}

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
            onClick={() => onApprove([...selected])}
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
    </AuthBackdrop>
  );
}
