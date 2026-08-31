'use client';

import { useEffect, useState } from 'react';
import { cachedUserInfo, loadUserInfo, type UserInfo } from './console';

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
