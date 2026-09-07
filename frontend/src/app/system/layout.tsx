'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { ConsoleMobileNav, ConsoleSidebar } from '../../components/ConsoleNav';
import { UserMenu } from '../../components/UserMenu';
import { RealmSwitcher } from '../../components/RealmSwitcher';
import { CrossRealmBanner } from '../../components/CrossRealmBanner';
import { currentClaims, isExpired, type Claims } from '../../lib/console';
import { usePermissions } from '../../lib/profile';
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

  /**
   * Read once here, at the shell, not per page.
   *
   * The sidebar and the mobile nav decide what to show with `can()`, which falls back to this same
   * read (the token carries roles, not entitlements, by default). Without this call somewhere above
   * every page, the nav renders once before anything has ever populated the cache and never learns
   * better: a page that itself calls the hook re-renders ITS OWN gated buttons, but nothing tells the
   * sidebar to look again. This is what does, and it re-renders the whole shell when the read lands.
   */
  usePermissions();

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
          {/* The page gutter is defined here so sections do not drift apart as you navigate. The
              content takes the width the sidebar leaves it, capped only on very wide screens where a
              table stretched edge to edge stops being readable. */}
          <div className="mx-auto w-full max-w-[120rem] px-2 py-4 sm:px-3 sm:py-5 lg:px-4">
            {children}
          </div>
        </div>
      </div>

      <ConsoleMobileNav claims={claims} />
    </div>
  );
}
