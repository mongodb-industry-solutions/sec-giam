'use client';

import { useCallback, useEffect, useState } from 'react';
import { callApi } from './console';
import { REALM_CHANGED_EVENT, setActiveRealm, storedHomeRealm, storedRealm } from './session';

/**
 * The realms this person may administer, and which of them the console is acting on.
 *
 * A principal has one home realm and may hold grants over others. The console never infers the set:
 * it asks, and the authority answers with what is actually granted, per realm, including the
 * permissions held there. Two realms are not the same job, and a switcher that showed only names
 * would hide that a grant is usually narrower away from home.
 */

export interface AdministrableRealm {
  realmId: string;
  name: string;
  displayName: string;
  home: boolean;
  roles: string[];
  permissions: Array<{ resource: string; action: string }>;
}

/**
 * Loads the list and tracks the current choice.
 *
 * Addressed at the HOME realm rather than the selected one, because a grant withdrawn while it was
 * selected would otherwise leave the switcher unable to answer the one question that would get the
 * person out again.
 */
export function useAdministrableRealms() {
  const [realms, setRealms] = useState<AdministrableRealm[]>([]);
  const [active, setActive] = useState('');
  const [home, setHome] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setActive(storedRealm());
    setHome(storedHomeRealm());

    callApi<{ realms: AdministrableRealm[] }>('/administrable-realms', {
      realm: storedHomeRealm(),
      subject: 'the realms you administer',
    })
      // A console that cannot read the list still works against the realm it signed into, so this
      // falls back to nothing rather than reporting a failure the person cannot act on.
      .then((body) => { if (!cancelled) setRealms(body.realms ?? []); })
      .catch(() => { if (!cancelled) setRealms([]); })
      .finally(() => { if (!cancelled) setLoading(false); });

    function onChanged() { setActive(storedRealm()); }
    window.addEventListener(REALM_CHANGED_EVENT, onChanged);
    return () => { cancelled = true; window.removeEventListener(REALM_CHANGED_EVENT, onChanged); };
  }, []);

  const select = useCallback((name: string) => {
    if (name === storedRealm()) return;
    setActiveRealm(name);
  }, []);

  const current = realms.find((realm) => realm.name === active) ?? null;
  return { realms, active, home, current, loading, select, crossRealm: Boolean(active && home && active !== home) };
}

/**
 * Re-runs a loader whenever the acting realm changes.
 *
 * Every screen reads a realm's records, so a switch that left the previous realm's rows on screen
 * would be showing one realm's data under another realm's name.
 */
export function useRealmChange(reload: () => void): void {
  useEffect(() => {
    window.addEventListener(REALM_CHANGED_EVENT, reload);
    return () => window.removeEventListener(REALM_CHANGED_EVENT, reload);
  }, [reload]);
}
