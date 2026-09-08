'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { ChevronDown, Globe, Home, KeyRound, Layers, LogOut, ShieldCheck, UserRound } from 'lucide-react';
import { displayName, initials, type Claims } from '../lib/console';
import { useUserInfo } from '../lib/profile';
import { REALM_CHANGED_EVENT, storedHomeRealm, storedRealm } from '../lib/session';

/**
 * The signed-in principal, and everything about them the console can offer.
 *
 * It names the subject and the realm as well as the person, because on an identity console "who am
 * I signed in as" is a question with three answers and showing only the friendly one hides the two
 * that decide what the API will allow.
 */
export function UserMenu({ claims, onSignOut }: { claims: Claims; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const [realm, setRealm] = useState('');
  const [home, setHome] = useState('');
  const ref = useRef<HTMLDivElement>(null);
  // Read for its side effect on the shared cache: the name below comes from it once it arrives.
  const { info } = useUserInfo();

  useEffect(() => {
    function read() { setRealm(storedRealm()); setHome(storedHomeRealm()); }
    read();
    window.addEventListener(REALM_CHANGED_EVENT, read);
    return () => window.removeEventListener(REALM_CHANGED_EVENT, read);
  }, []);

  useEffect(() => {
    function onDown(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  const roles = claims.roles ?? [];
  const who = displayName(claims);
  const email = typeof info?.email === 'string' ? info.email : '';

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={`Account menu for ${who}`}
        className={`flex items-center gap-2 rounded-lg border py-1 pl-1 pr-2 transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
          open ? 'border-white/20 bg-white/10' : 'border-transparent hover:border-white/10 hover:bg-white/10'
        }`}
      >
        <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-[#00ED64] text-xs font-bold text-[#001E2B]">
          {initials(claims)}
        </span>
        <span className="hidden flex-col items-start leading-none sm:flex">
          <span className="max-w-32 truncate text-xs font-semibold text-white">{who}</span>
          <span className="max-w-32 truncate text-[10px] font-medium text-gray-400">
            {roles[0] ?? 'no role assigned'}
          </span>
        </span>
        <ChevronDown size={13} className={`shrink-0 text-gray-400 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Account"
          className="fixed inset-x-2 top-14 z-50 w-auto overflow-hidden rounded-xl border border-white/10 bg-[#0d2a38] shadow-2xl shadow-black/40 sm:absolute sm:inset-x-auto sm:right-0 sm:top-full sm:mt-2 sm:w-72"
        >
          <div className="border-b border-white/10 px-4 py-3.5">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#00ED64] text-sm font-bold text-[#001E2B]">
                {initials(claims)}
              </span>
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-white">{who}</p>
                {/* The name and the address, which is what identifies a person to themselves. The
                    subject id lives on the profile screen: it is an opaque identifier, it says
                    nothing anybody can act on here, and it is not a name. */}
                {email && <p className="truncate text-[11px] text-gray-300" title={email}>{email}</p>}
              </div>
            </div>

            <dl className="mt-3 space-y-1.5">
              {/* Home is where the identity, the credentials and the signing key live; acting is
                  where the requests go. They differ only under a cross-realm grant, and when they do
                  it is the thing most worth reading here. */}
              <div className="flex items-baseline gap-2">
                <dt className="w-12 shrink-0 text-[10px] uppercase tracking-wider text-gray-500">Home</dt>
                <dd className="truncate text-xs text-gray-200">{home || 'unknown'}</dd>
              </div>
              <div className="flex items-baseline gap-2">
                <dt className="w-12 shrink-0 text-[10px] uppercase tracking-wider text-gray-500">Acting</dt>
                <dd className="flex min-w-0 items-center gap-1.5 truncate text-xs text-gray-200">
                  {realm || 'unknown'}
                  {realm && home && realm !== home && (
                    <span className="inline-flex shrink-0 items-center gap-1 rounded border border-amber-400/40 bg-amber-400/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-amber-200">
                      <Globe size={9} aria-hidden />
                      granted
                    </span>
                  )}
                </dd>
              </div>
              <div className="flex items-baseline gap-2">
                <dt className="w-12 shrink-0 text-[10px] uppercase tracking-wider text-gray-500">Roles</dt>
                <dd className="flex min-w-0 flex-wrap gap-1">
                  {roles.length === 0
                    ? <span className="text-xs text-gray-400">none assigned</span>
                    : roles.map((role) => (
                        <span key={role} className="rounded border border-[#00ED64]/30 bg-[#00ED64]/10 px-1.5 py-0.5 text-[10px] font-medium text-[#00ED64]">
                          {role}
                        </span>
                      ))}
                </dd>
              </div>
            </dl>
          </div>

          <div className="py-1.5">
            <MenuLink href="/system/profile" icon={UserRound} label="Your profile" onClick={() => setOpen(false)} />
            <MenuLink href="/system/credentials" icon={KeyRound} label="Your authenticators" onClick={() => setOpen(false)} />
            <MenuLink href="/system/applications" icon={Layers} label="Authorized applications" onClick={() => setOpen(false)} />
            <MenuLink href="/system/activity" icon={ShieldCheck} label="Your activity" onClick={() => setOpen(false)} />
            <MenuLink href="/system/realm-grants" icon={Globe} label="Cross-realm administration" onClick={() => setOpen(false)} />
            <MenuLink href="/" icon={Home} label="Back to Mode Selection" onClick={() => setOpen(false)} />

            <div className="mx-3 my-1 border-t border-white/10" />

            <button
              type="button"
              role="menuitem"
              onClick={() => { setOpen(false); onSignOut(); }}
              className="flex w-full items-center gap-3 px-4 py-2.5 text-left text-sm text-gray-200 transition-colors hover:bg-red-500/10 hover:text-red-300 focus:outline-none focus-visible:bg-red-500/10"
            >
              <LogOut size={15} className="shrink-0 text-gray-400" />
              <span>Sign out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function MenuLink({ href, icon: Icon, label, onClick }: {
  href: string;
  icon: typeof KeyRound;
  label: string;
  onClick: () => void;
}) {
  return (
    <Link
      href={href}
      role="menuitem"
      onClick={onClick}
      className="flex items-center gap-3 px-4 py-2.5 text-sm text-gray-200 transition-colors hover:bg-white/10 hover:text-white focus:outline-none focus-visible:bg-white/10"
    >
      <Icon size={15} className="shrink-0 text-gray-400" />
      <span>{label}</span>
    </Link>
  );
}
