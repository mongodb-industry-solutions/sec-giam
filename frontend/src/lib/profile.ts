'use client';

import { useCallback, useEffect, useState } from 'react';
import { cachedPermissions, cachedUserInfo, loadPermissions, loadUserInfo, type MyPermissions, type UserInfo } from './console';
import { useRealmChange } from './realms';

/**
 * The signed-in person's profile, for any screen that needs to name them.
 *
 * The read happens once per session and is shared, so a header, a menu and a page asking at the same
 * moment produce one request between them. A failure leaves the value null and nothing else: the
 * caller keeps rendering from the token.
 */
export function useUserInfo(): { info: UserInfo | null; loading: boolean } {
  const [info, setInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let live = true;
    const cached = cachedUserInfo();
    if (cached) {
      setInfo(cached);
      setLoading(false);
      return;
    }
    void loadUserInfo().then((value) => {
      if (!live) return;
      setInfo(value);
      setLoading(false);
    });
    return () => { live = false; };
  }, []);

  return { info, loading };
}

/**
 * The signed-in principal's own effective permissions, for any screen that gates a control on
 * `can()`. `can()` alone reads a cache that starts empty every realm switch; this is what fills it
 * and forces the one re-render that makes the gate reconsider once the read comes back.
 */
export function usePermissions(): { permissions: MyPermissions | null; loading: boolean } {
  const [permissions, setPermissions] = useState<MyPermissions | null>(null);
  const [loading, setLoading] = useState(true);

  const read = useCallback(() => {
    let live = true;
    const cached = cachedPermissions();
    if (cached) {
      setPermissions(cached);
      setLoading(false);
      return () => { live = false; };
    }
    setLoading(true);
    void loadPermissions().then((value) => {
      if (!live) return;
      setPermissions(value);
      setLoading(false);
    });
    return () => { live = false; };
  }, []);

  useEffect(() => read(), [read]);
  // The answer is a property of the realm being acted on: a switch invalidates the cache (console.ts)
  // and this is what asks again, rather than leaving the last realm's controls on screen.
  useRealmChange(read);

  return { permissions, loading };
}
