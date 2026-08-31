'use client';

import { useEffect, useRef, useState } from 'react';
import { Check, ChevronDown, Globe, Home } from 'lucide-react';
import { useAdministrableRealms, type AdministrableRealm } from '../lib/realms';

/**
 * Which realm the console is acting on, and how to change it.
 *
 * Absent entirely when there is only one realm to act on, because a control with a single option is
 * noise that teaches nothing. Present and loud otherwise: acting on the wrong realm is the mistake
 * this capability makes possible, so the realm is named in the header at all times rather than
 * hidden behind a menu, and a realm that is not the person's own is coloured differently from the
 * one that is.
 */
export function RealmSwitcher() {
  const { realms, active, current, select, crossRealm } = useAdministrableRealms();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

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

  // One realm is the ordinary case, and it gets no control at all.
  if (realms.length < 2) return null;

  const label = current?.displayName || active;

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-haspopup="listbox"
        aria-label={`Acting on realm ${label}. Change realm.`}
        className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
          crossRealm
            ? 'border-amber-400/60 bg-amber-400/15 text-amber-200 hover:bg-amber-400/25'
            : 'border-white/15 bg-white/5 text-gray-200 hover:bg-white/10'
        }`}
      >
        {crossRealm ? <Globe size={13} aria-hidden /> : <Home size={13} aria-hidden />}
        <span className="max-w-40 truncate">{label}</span>
        {crossRealm && <span className="hidden text-[10px] font-bold uppercase tracking-wider sm:inline">not your realm</span>}
        <ChevronDown size={12} className={`shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="Realm"
          className="fixed inset-x-2 top-14 z-50 overflow-hidden rounded-xl border border-white/10 bg-[#0d2a38] shadow-2xl shadow-black/40 sm:absolute sm:inset-x-auto sm:left-0 sm:top-full sm:mt-2 sm:w-80"
        >
          <p className="border-b border-white/10 px-4 py-2.5 text-[10px] uppercase tracking-wider text-gray-500">
            Acting on realm
          </p>
          <ul className="max-h-96 overflow-y-auto py-1.5">
            {realms.map((realm) => (
              <li key={realm.realmId}>
                <RealmOption
                  realm={realm}
                  selected={realm.name === active}
                  onSelect={() => { select(realm.name); setOpen(false); }}
                />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function RealmOption({ realm, selected, onSelect }: {
  realm: AdministrableRealm;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      onClick={onSelect}
      className={`flex w-full items-start gap-2.5 px-4 py-2.5 text-left transition-colors focus:outline-none focus-visible:bg-white/10 ${
        selected ? 'bg-white/10' : 'hover:bg-white/5'
      }`}
    >
      <Check size={14} className={`mt-0.5 shrink-0 ${selected ? 'text-[#00ED64]' : 'text-transparent'}`} aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-2">
          <span className="truncate text-sm font-semibold text-white">{realm.displayName}</span>
          <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider ${
            realm.home
              ? 'border-[#00ED64]/30 bg-[#00ED64]/10 text-[#00ED64]'
              : 'border-amber-400/40 bg-amber-400/10 text-amber-200'
          }`}
          >
            {realm.home ? 'your realm' : 'granted'}
          </span>
        </span>
        <span className="mt-0.5 block truncate font-mono text-[10px] text-gray-400">{realm.name}</span>
        {/* What the grant actually carries. A switcher that showed only names would let somebody
            assume their authority travels with them, and away from home it usually does not. */}
        <span className="mt-1 block text-[10px] text-gray-400">
          {realm.roles.length > 0 ? realm.roles.join(', ') : 'no role'}
          {' · '}
          {realm.permissions.length} permission{realm.permissions.length === 1 ? '' : 's'}
        </span>
      </span>
    </button>
  );
}
