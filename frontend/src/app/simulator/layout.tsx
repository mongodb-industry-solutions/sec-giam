'use client';

import Link from 'next/link';
import { useEffect } from 'react';
import { ShieldCheck, ChevronLeft } from 'lucide-react';
import { BRAND } from '../../config/brand';

export default function SimulatorLayout({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    document.title = `${BRAND.full} - Simulator`;
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="flex items-center justify-between gap-2 bg-[#001E2B] px-3 py-3 text-white shadow-lg sm:px-4">
        <Link href="/simulator" className="flex shrink-0 items-center gap-1.5 transition-opacity hover:opacity-80">
          <ShieldCheck size={18} className="text-[#00ED64]" />
          <span className="hidden text-sm font-bold text-[#00ED64] md:block">{BRAND.full} Simulator</span>
          <span className="text-xs font-bold text-[#00ED64] md:hidden">{BRAND.primary}</span>
        </Link>
        <div className="flex shrink-0 items-center gap-2">
          <span className="hidden rounded border border-gray-600 px-2 py-0.5 text-xs text-gray-400 sm:inline">
            Simulator
          </span>
          <Link href="/simulator" className="flex items-center gap-0.5 text-xs text-gray-400 transition-colors hover:text-white">
            <ChevronLeft size={13} />
            <span className="hidden sm:block">Menu</span>
          </Link>
          <Link href="/" className="text-xs text-gray-400 transition-colors hover:text-white">
            Exit
          </Link>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-3 py-4 sm:px-6 sm:py-6">{children}</main>
    </div>
  );
}
