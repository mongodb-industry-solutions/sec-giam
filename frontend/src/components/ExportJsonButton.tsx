'use client';

import { useState } from 'react';
import { Download } from 'lucide-react';
import { downloadFile } from '../lib/download';

/**
 * Downloads what the current filters select as a JSON document.
 *
 * `build` runs at click time, and may fetch, so the file holds every match rather than the page on
 * screen. It should carry the filters, so the file says what it is a slice of.
 */
export function ExportJsonButton({ filename, count, build, disabled, noun = 'entries', onError }: {
  filename: string;
  count: number;
  build: () => unknown | Promise<unknown>;
  disabled?: boolean;
  noun?: string;
  onError?: (failure: unknown) => void;
}) {
  const [busy, setBusy] = useState(false);
  const empty = count === 0;

  async function run() {
    setBusy(true);
    try {
      const payload = await build();
      downloadFile(`${filename}-${Date.now()}.json`, JSON.stringify(payload, null, 2), 'application/json');
    } catch (failure) {
      onError?.(failure);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      type="button"
      onClick={() => void run()}
      disabled={disabled || empty || busy}
      title={empty ? 'Nothing matches this search yet' : `Download ${count} ${noun} as JSON`}
      className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-3 text-xs font-semibold text-[#001E2B] transition-colors hover:border-[#001E2B] hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#001E2B]/20 disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Download size={13} aria-hidden />
      {busy ? 'Preparing…' : 'Download JSON'}
    </button>
  );
}
