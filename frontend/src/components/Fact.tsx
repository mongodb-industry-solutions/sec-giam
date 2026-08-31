'use client';

import type { ReactNode } from 'react';

/** One labelled value in a record's detail panel, so every section reads the same way. */
export function Fact({ label, value, mono, children }: {
  label: string;
  value?: string;
  mono?: boolean;
  children?: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className={`truncate text-gray-700 ${mono ? 'font-mono text-xs' : ''}`} title={value}>
        {children ?? value ?? 'not set'}
      </dd>
    </div>
  );
}
