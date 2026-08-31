'use client';

import type { ReactNode } from 'react';
import { AlertTriangle, Inbox, Loader2, RotateCw, type LucideIcon } from 'lucide-react';

/**
 * The three things a list can be other than a list.
 *
 * Kept in one place so every section says "nothing yet" and "this failed because" the same way. An
 * error states what failed, because "something went wrong" tells a reader nothing they can act on.
 */

export function LoadingState({ label }: { label: string }) {
  return (
    <div className="flex items-center justify-center gap-2.5 rounded-xl border border-gray-200 bg-white px-6 py-12 text-sm text-gray-500" role="status">
      <Loader2 size={16} className="animate-spin text-[#001E2B]" aria-hidden />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }: {
  icon?: LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-dashed border-gray-300 bg-white px-6 py-12 text-center">
      <Icon size={28} className="mx-auto text-gray-300" aria-hidden />
      <p className="mt-3 font-medium text-[#001E2B]">{title}</p>
      <p className="mx-auto mt-1 max-w-md text-sm text-gray-500">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-4">
      <div className="flex items-start gap-2.5">
        <AlertTriangle size={16} className="mt-0.5 shrink-0 text-red-600" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-red-800">{message}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-2.5 inline-flex items-center gap-1.5 rounded-md border border-red-300 bg-white px-2.5 py-1.5 text-xs font-medium text-red-700 transition-colors hover:bg-red-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
            >
              <RotateCw size={12} aria-hidden />
              Try again
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/** A small coloured label for a record's state, used wherever a list shows one. */
export function StatusBadge({ status }: { status: string }) {
  const tone = /active|success|in-force|approved/i.test(status)
    ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
    : /revoked|failure|denied|expired/i.test(status)
      ? 'border-red-200 bg-red-50 text-red-700'
      : /pending|waiting/i.test(status)
        ? 'border-amber-200 bg-amber-50 text-amber-700'
        : 'border-gray-200 bg-gray-50 text-gray-600';
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${tone}`}>
      {status}
    </span>
  );
}
