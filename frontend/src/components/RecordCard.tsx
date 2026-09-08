'use client';

import type { ReactNode } from 'react';
import { Loader2, type LucideIcon } from 'lucide-react';

/**
 * The row shape the administrative sections share.
 *
 * Roles, keys and sessions are the same object on screen: a title, a few facts, and the operations
 * the caller's token allows on it. Written once, because a copy per section is how three lists end
 * up with three different ideas of what a disabled button looks like.
 */

export function RecordCard({ title, subtitle, badges, facts, actions, children }: {
  title: ReactNode;
  /** The identifier, usually. Monospaced, because it is read character by character. */
  subtitle?: ReactNode;
  badges?: ReactNode;
  facts?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <li className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-[#001E2B]">{title}</span>
            {badges}
          </div>
          {subtitle && <p className="mt-0.5 truncate font-mono text-xs text-gray-400">{subtitle}</p>}
          {facts && <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-3">{facts}</dl>}
          {children}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap gap-2">{actions}</div>}
      </div>
    </li>
  );
}

/** One labelled value. Truncated with the full text on hover, so a long identifier never wraps a row. */
export function Fact({ label, value, title }: { label: string; value: ReactNode; title?: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className="truncate text-gray-700" title={title ?? (typeof value === 'string' ? value : undefined)}>{value}</dd>
    </div>
  );
}

type Tone = 'neutral' | 'danger' | 'primary';

const TONES: Record<Tone, string> = {
  neutral: 'border-gray-200 text-gray-700 hover:bg-gray-50 focus-visible:ring-gray-400',
  danger: 'border-red-200 text-red-700 hover:bg-red-50 focus-visible:ring-red-500',
  primary: 'border-[#001E2B] bg-[#001E2B] text-[#00ED64] hover:bg-[#00303f] focus-visible:ring-[#00ED64]',
};

/** A control that is only rendered when the API would accept it, and disabled while it is in flight. */
export function ActionButton({ icon: Icon, label, tone = 'neutral', busy, disabled, onClick }: {
  icon: LucideIcon;
  label: string;
  tone?: Tone;
  busy?: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      disabled={busy || disabled}
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 disabled:opacity-50 ${TONES[tone]}`}
    >
      {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Icon size={12} aria-hidden />}
      {label}
    </button>
  );
}
