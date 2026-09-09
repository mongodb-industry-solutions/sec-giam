'use client';
import { useState, useRef, useEffect, useSyncExternalStore } from 'react';
import { API_BASE_URL } from '../../../../lib/constants';
import { getAdminToken, LogEntry, downloadText, readSSE } from '../../../../lib/adminHelpers';
import { Download, Copy, CheckCheck, Play, Square } from 'lucide-react';

// ---------------------------------------------------------------------------
//  Module-level stream manager: persists across tab switches (mount/unmount)
// ---------------------------------------------------------------------------

const LOGS_KEY = 'admin_server_logs';
const MAX_LOGS = 1000;
const PERSIST_LIMIT = 500;

let _logs: LogEntry[] = (() => {
  if (typeof window === 'undefined') return [];
  try { return JSON.parse(sessionStorage.getItem(LOGS_KEY) ?? '[]'); } catch { return []; }
})();
let _streaming = false;
let _stopped = true;          // user intent: false while the live view should stay connected
let _controller: AbortController | null = null;
// Reconnect backoff. Capped so a long backend outage cannot burn the /admin ops rate limit
// (300 requests / 15 min, i.e. 1 every 3s) and leave the live view permanently 429-ed.
const RECONNECT_DELAY_MS = 3000;
const RECONNECT_DELAY_MAX_MS = 30_000;
// The server heartbeats every 15s, so a longer silence means the stream is gone (dropped by a proxy).
const IDLE_TIMEOUT_MS = 45_000;
const _listeners = new Set<() => void>();

function _notify() { _listeners.forEach((fn) => fn()); }

function _push(entry: LogEntry) {
  _logs = [..._logs.slice(-(MAX_LOGS - 1)), entry];
  sessionStorage.setItem(LOGS_KEY, JSON.stringify(_logs.slice(-PERSIST_LIMIT)));
  _notify();
}

/**
 * Keeps the live view connected until the user presses Stop. A dropped stream (proxy idle timeout,
 * backend restart) is reconnected automatically; the reconnect skips the buffered snapshot so the
 * already-rendered lines are not duplicated.
 */
async function _start() {
  if (!getAdminToken() || _streaming) return;

  _stopped = false;
  _streaming = true;
  _notify();
  let first = true;
  let delay = RECONNECT_DELAY_MS;

  try {
    while (!_stopped) {
      const token = getAdminToken();
      if (!token) { _push({ type: 'error', text: 'Admin session expired.' }); break; }
      _controller = new AbortController();
      try {
        const res = await fetch(`${API_BASE_URL}/api/v1/admin/logs/stream${first ? '' : '?snapshot=false'}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: _controller.signal,
        });
        if (!res.ok || !res.body) {
          // An HTTP-level rejection (401, 429) will not fix itself; stop instead of hammering.
          _push({ type: 'error', text: `HTTP ${res.status}: ${res.statusText}` });
          break;
        }
        first = false;
        delay = RECONNECT_DELAY_MS;   // a successful connection resets the backoff
        await readSSE(res, (type, text) => _push({ type: type === 'error' ? 'error' : 'log', text }), undefined, IDLE_TIMEOUT_MS);
        if (_stopped) break;
        _push({ type: 'error', text: '-- log stream ended, reconnecting... --' });
      } catch (err: unknown) {
        if (_stopped || (err instanceof DOMException && err.name === 'AbortError')) break;
        _push({ type: 'error', text: `-- log stream lost (${(err as Error).message}), reconnecting... --` });
      }
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, RECONNECT_DELAY_MAX_MS);
    }
  } finally {
    _streaming = false;
    _controller = null;
    _notify();
  }
}

function _stop() {
  _stopped = true;
  _controller?.abort();
  _controller = null;
  _streaming = false;
  _notify();
}

function _clear() {
  _logs = [];
  sessionStorage.removeItem(LOGS_KEY);
  _notify();
}

function subscribe(cb: () => void) {
  _listeners.add(cb);
  return () => { _listeners.delete(cb); };
}
function getLogsSnapshot() { return _logs; }
function getStreamingSnapshot() { return _streaming; }

// ---------------------------------------------------------------------------
//  Component: subscribes to the module-level store via useSyncExternalStore
// ---------------------------------------------------------------------------

export default function LogsPage() {
  const logs = useSyncExternalStore(subscribe, getLogsSnapshot, () => []);
  const streaming = useSyncExternalStore(subscribe, getStreamingSnapshot, () => false);

  const [copied, setCopied] = useState(false);
  const [filter, setFilter] = useState('');
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  function handleCopy() {
    const text = logs.map((e) => e.text).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const filtered = filter
    ? logs.filter((e) => e.text.toLowerCase().includes(filter.toLowerCase()))
    : logs;

  return (
    <div className="flex flex-col h-[65vh] lg:h-full bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950 gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-gray-400">Server Logs</span>
          {streaming && (
            <span className="inline-flex items-center gap-1 text-xs text-green-400">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
              live
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter..."
            className="bg-gray-800 text-xs text-gray-300 px-2 py-1 rounded border border-gray-700 focus:outline-none focus:border-gray-500 w-32"
          />
          <button
            onClick={streaming ? _stop : _start}
            className={`inline-flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors ${
              streaming
                ? 'bg-red-600/20 text-red-400 hover:bg-red-600/30'
                : 'bg-green-600/20 text-green-400 hover:bg-green-600/30'
            }`}
          >
            {streaming ? <><Square size={10} /> Stop</> : <><Play size={10} /> Stream</>}
          </button>
          <button
            onClick={handleCopy}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Copy all output"
          >
            {copied ? <CheckCheck size={12} /> : <Copy size={12} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button
            onClick={() => downloadText(`server-logs-${Date.now()}.txt`, logs.map((e) => e.text).join('\n'))}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Download logs"
          >
            <Download size={12} /> Download
          </button>
          <button onClick={_clear} className="text-xs text-gray-600 hover:text-gray-400">Clear</button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-0.5 [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70 [&::-webkit-scrollbar-corner]:bg-gray-900">
        {filtered.length === 0 && !streaming && (
          <div className="text-gray-600 italic">
            Click &quot;Stream&quot; to start receiving server logs in real time...
          </div>
        )}
        {filtered.length === 0 && streaming && (
          <div className="text-gray-500 animate-pulse">Waiting for log entries...</div>
        )}
        {filtered.map((e, i) => (
          <div key={i} className={e.type === 'error' ? 'text-red-400' : 'text-gray-200'}>
            {e.text}
          </div>
        ))}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
