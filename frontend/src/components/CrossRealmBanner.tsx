'use client';

import { Globe, Undo2 } from 'lucide-react';
import { useAdministrableRealms } from '../lib/realms';

/**
 * A standing statement that this is not your realm.
 *
 * Full width, above every screen, and not dismissible. Acting on the wrong realm is the single
 * mistake the switcher makes possible, and the moment somebody has to remember which realm they
 * chose is the moment they get it wrong. The way back is offered here rather than only in the
 * switcher, because leaving should be easier than arriving.
 */
export function CrossRealmBanner() {
  const { crossRealm, current, active, home, select } = useAdministrableRealms();
  if (!crossRealm) return null;

  return (
    <div role="status" className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 border-b border-amber-300 bg-amber-100 px-4 py-2 text-center text-xs text-amber-900">
      <Globe size={14} className="shrink-0" aria-hidden />
      <span>
        You are administering <strong className="font-bold">{current?.displayName || active}</strong>, which is not your own realm.
        {current?.roles.length ? <> Your grant there is <strong className="font-semibold">{current.roles.join(', ')}</strong>.</> : null}
      </span>
      <button
        type="button"
        onClick={() => select(home)}
        className="inline-flex items-center gap-1.5 rounded-md border border-amber-400 bg-white px-2 py-1 font-semibold text-amber-900 transition-colors hover:bg-amber-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-600"
      >
        <Undo2 size={12} aria-hidden />
        Back to {home}
      </button>
    </div>
  );
}
