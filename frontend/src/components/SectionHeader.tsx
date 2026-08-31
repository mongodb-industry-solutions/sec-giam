'use client';

import type { ReactNode } from 'react';
import { Info, type LucideIcon } from 'lucide-react';

/** The same heading on every console section, so a reader always knows where they are and why. */
export function SectionHeader({ icon: Icon, title, description, info, actions }: {
  icon: LucideIcon;
  title: string;
  description: string;
  /** A longer explanation, when the section needs one to be understood on first sight. */
  info?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#001E2B]">
            <Icon size={20} className="text-[#00ED64]" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-bold leading-tight text-[#001E2B]">{title}</h1>
            <p className="mt-0.5 text-sm text-gray-500">{description}</p>
          </div>
        </div>
        {actions && <div className="shrink-0">{actions}</div>}
      </div>

      {info && (
        <div className="flex items-start gap-2 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2.5 text-sm leading-relaxed text-blue-800">
          <Info size={15} className="mt-0.5 shrink-0 text-blue-600" />
          <div className="min-w-0">{info}</div>
        </div>
      )}
    </div>
  );
}
