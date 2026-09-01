'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ConsoleMobileNav, ConsoleSidebar } from '../../components/ConsoleNav';
import { UserMenu } from '../../components/UserMenu';
import { RealmSwitcher } from '../../components/RealmSwitcher';
import { CrossRealmBanner } from '../../components/CrossRealmBanner';
import { currentClaims, isExpired, type Claims } from '../../lib/console';
import { SESSION_CHANGED_EVENT } from '../../lib/session';
import { BRAND } from '../../config/brand';

/**
 * The shell every signed-in console screen sits in.
 *
 * The overview page carries the sign-in form itself, so when nobody is signed in the shell steps out
 * of the way rather than framing an empty console. Any other section reached without a session sends
 * the person to the overview to sign in, because a section that renders its own sign-in prompt is a
 * second place for that form to drift from the first.
 */
export default function ConsoleLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [claims, setClaims] = useState<Claims | null>(null);
  const [checked, setChecked] = useState(false);

  const refresh = useCallback(() => {
    const found = currentClaims();
    setClaims(found && !isExpired(found) ? found : null);
    setChecked(true);
  }, []);

  useEffect(() => { refresh(); }, [pathname, refresh]);

  // Signing in happens on the overview, which is INSIDE this shell, so the address never changes and
  // the effect above never runs again. Listening for the session itself is what makes the header and
  // the sidebar appear on sign-in rather than on the next reload.
  useEffect(() => {
    window.addEventListener(SESSION_CHANGED_EVENT, refresh);
    return () => window.removeEventListener(SESSION_CHANGED_EVENT, refresh);
  }, [refresh]);

  useEffect(() => {
    if (checked && !claims && pathname !== '/system') router.replace('/system');
  }, [checked, claims, pathname, router]);

  if (!checked) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#001E2B] text-sm text-gray-400">
        Checking your session…
      </main>
    );
  }

  // Signed out on the overview: that page owns the sign-in form and needs the full width for it.
  if (!claims) return <>{children}</>;

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-40 flex h-12 shrink-0 items-center justify-between gap-3 border-b border-white/10 bg-[#001E2B] px-3 sm:px-5">
        <Link
          href="/system"
          className="flex items-center gap-2 rounded text-sm font-bold whitespace-nowrap text-[#00ED64] transition-colors hover:text-[#00ED64]/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/app-icon.png" alt="" aria-hidden className="h-8 w-8" />
          <span className="text-white">{BRAND.primary}</span>
          {BRAND.secondary && <span>{BRAND.secondary}</span>}
          <span className="hidden text-[11px] font-normal text-gray-400 lg:inline">{BRAND.expansion}</span>
        </Link>

        <div className="flex items-center gap-2">
          <RealmSwitcher />
          <UserMenu claims={claims} onSignOut={() => router.push('/auth/logout?redirect=/system')} />
        </div>
      </header>

      <div className="flex flex-1">
        <ConsoleSidebar claims={claims} />
        <div className="min-w-0 flex-1 bg-gray-50 pb-16 md:pb-0">
          <CrossRealmBanner />
          {/* The page gutter is defined here so sections do not drift apart as you navigate. */}
          <div className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-6 lg:px-8">
            {children}
          </div>
        </div>
      </div>

      <ConsoleMobileNav claims={claims} />
    </div>
  );
}
