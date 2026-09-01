'use client';

import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../lib/constants';

// The version actually running, read from the authority's health endpoint.
// A build-time constant would report the version the console was built from, not the one answering.
export function ReleaseVersion() {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    fetch(`${API_BASE_URL}/health`, { cache: 'no-store' })
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => { if (live && body?.version) setVersion(body.version as string); })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  // Omitted rather than guessed: a wrong version is worse than no version.
  if (!version) return null;
  return <>v{version} · </>;
}
