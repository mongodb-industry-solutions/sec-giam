'use client';

import { useState } from 'react';
import { Check, Copy, KeyRound, X } from 'lucide-react';

/**
 * A credential the authority will never show again.
 *
 * The authority stores only a hash of it, so this panel is the single moment the value exists outside
 * the application that will use it. It says so plainly rather than relying on the reader to know,
 * because "we can look it up for you" and "anyone who reaches this can have it" are the same sentence.
 */
export function SecretOnce({ clientId, secret, onDismiss }: {
  clientId: string;
  secret: string;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be refused. The value is on screen and selectable either way.
      setCopied(false);
    }
  }

  return (
    <section role="alert" className="rounded-xl border border-amber-300 bg-amber-50 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <KeyRound size={16} className="mt-0.5 shrink-0 text-amber-700" aria-hidden />
          <div className="min-w-0">
            <p className="text-sm font-semibold text-amber-900">
              Copy this secret now. It will not be shown again.
            </p>
            <p className="mt-0.5 text-xs text-amber-800">
              The authority keeps only a hash of it, so nobody can retrieve it later. If it is lost,
              rotate the secret and update the application with the new one.
            </p>
          </div>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="shrink-0 rounded-md p-1 text-amber-700 transition-colors hover:bg-amber-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-600"
        >
          <X size={14} aria-hidden />
        </button>
      </div>

      <dl className="mt-3 space-y-2">
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-amber-700">Client id</dt>
          <dd className="break-all font-mono text-xs text-amber-900">{clientId}</dd>
        </div>
        <div>
          <dt className="text-[10px] uppercase tracking-wider text-amber-700">Client secret</dt>
          <dd className="mt-1 flex items-start gap-2">
            <code className="min-w-0 flex-1 break-all rounded-md border border-amber-300 bg-white px-2.5 py-2 font-mono text-xs text-[#001E2B]">
              {secret}
            </code>
            <button
              type="button"
              onClick={() => void copy()}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-amber-400 bg-white px-2.5 py-2 text-xs font-medium text-amber-900 transition-colors hover:bg-amber-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-600"
            >
              {copied ? <><Check size={12} aria-hidden /> Copied</> : <><Copy size={12} aria-hidden /> Copy</>}
            </button>
          </dd>
        </div>
      </dl>
    </section>
  );
}
