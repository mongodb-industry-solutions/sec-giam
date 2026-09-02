'use client';

import { useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { QrCode, Copy, Check } from 'lucide-react';

/**
 * A scannable address, plus the same address in copyable text.
 *
 * The code is encoded in the browser, never by an external service: handing a demo URL to a third
 * party to draw is a needless disclosure, and an offline environment would lose the picture with it.
 */
export function QrCodePanel({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const target = value;

  async function copy() {
    try {
      await navigator.clipboard.writeText(target);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard unavailable, the text is still on screen */ }
  }

  return (
    <div className="space-y-3 rounded-lg border border-gray-200 bg-white p-4">
      <div className="flex items-center gap-2 text-gray-700">
        <QrCode size={18} />
        <span className="text-sm font-medium">{label ?? 'Scan to open'}</span>
      </div>

      <div className="flex flex-col items-center justify-center rounded-md border border-gray-200 bg-white p-6">
        <QRCodeSVG value={target} size={192} level="M" marginSize={2} />
        <p className="mt-3 text-xs text-gray-500">Scan with a phone, or use the link below</p>
      </div>

      <div className="flex items-center gap-2">
        <code className="flex-1 truncate rounded bg-gray-100 px-2 py-1.5 text-xs text-gray-700" title={target}>{target}</code>
        <button
          type="button"
          onClick={copy}
          className="inline-flex items-center gap-1 rounded-md border border-gray-300 px-2.5 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50"
        >
          {copied ? <Check size={14} className="text-emerald-600" /> : <Copy size={14} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </div>
  );
}

export default QrCodePanel;
