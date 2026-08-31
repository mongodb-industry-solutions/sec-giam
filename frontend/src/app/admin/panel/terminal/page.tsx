'use client';
import { useState, useRef, useEffect } from 'react';
import { API_BASE_URL } from '../../../../lib/constants';
import { getAdminToken, readSSE, LogEntry, downloadText } from '../../../../lib/adminHelpers';
import { Download, Copy, CheckCheck } from 'lucide-react';

const TERMINAL_LOGS_KEY    = 'admin_terminal_logs';
const TERMINAL_HISTORY_KEY = 'admin_terminal_history';

export default function TerminalPage() {
  const [termInput, setTermInput] = useState('');
  const [termLogs, setTermLogs] = useState<LogEntry[]>([]);
  const [termRunning, setTermRunning] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [copied, setCopied] = useState(false);
  const termEndRef = useRef<HTMLDivElement>(null);
  const termInputRef = useRef<HTMLInputElement>(null);
  const [logsLoaded, setLogsLoaded] = useState(false);

  function handleCopy() {
    const text = termLogs.map((e) => e.text).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  // Restore logs and history from sessionStorage on mount.
  // All setState calls here are batched by React 18 into one render.
  useEffect(() => {
    const savedLogs = sessionStorage.getItem(TERMINAL_LOGS_KEY);
    if (savedLogs) {
      try { setTermLogs(JSON.parse(savedLogs)); } catch { /* ignore corrupt data */ }
    }
    const savedHistory = sessionStorage.getItem(TERMINAL_HISTORY_KEY);
    if (savedHistory) {
      try { setHistory(JSON.parse(savedHistory)); } catch { /* ignore corrupt data */ }
    }
    setLogsLoaded(true);
  }, []);

  // Persist logs after load is complete. Remove the key when empty (e.g. after Clear).
  useEffect(() => {
    if (!logsLoaded) return;
    if (termLogs.length === 0) sessionStorage.removeItem(TERMINAL_LOGS_KEY);
    else sessionStorage.setItem(TERMINAL_LOGS_KEY, JSON.stringify(termLogs));
  }, [termLogs, logsLoaded]);

  // Persist command history (keep even when empty - preserves arrow-key history)
  useEffect(() => {
    if (!logsLoaded) return;
    sessionStorage.setItem(TERMINAL_HISTORY_KEY, JSON.stringify(history));
  }, [history, logsLoaded]);

  useEffect(() => {
    termEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [termLogs]);

  useEffect(() => {
    termInputRef.current?.focus();
  }, [termRunning]);

  async function execCommand(cmd: string) {
    const token = getAdminToken();
    if (termRunning || !token || !cmd.trim()) return;
    const trimmed = cmd.trim();
    setHistory((h) => [trimmed, ...h.slice(0, 49)]);
    setHistoryIdx(-1);
    setTermInput('');
    setTermRunning(true);
    setTermLogs((prev) => [...prev, { type: 'start', text: `$ ${trimmed}` }]);
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/admin/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ command: trimmed }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        setTermLogs((prev) => [...prev, { type: 'error', text: (err as { error?: string }).error ?? 'Failed' }]);
        return;
      }
      await readSSE(res, (type, text) => {
        if (type !== 'start') {
          setTermLogs((prev) => [...prev, { type: type as LogEntry['type'], text }]);
        }
      });
    } finally {
      setTermRunning(false);
    }
  }

  function handleTermKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') { execCommand(termInput); return; }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHistoryIdx((i) => {
        const next = Math.min(i + 1, history.length - 1);
        if (history[next] !== undefined) setTermInput(history[next]);
        return next;
      });
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHistoryIdx((i) => {
        const next = Math.max(i - 1, -1);
        setTermInput(next === -1 ? '' : (history[next] ?? ''));
        return next;
      });
    }
  }

  return (
    <div
      className="flex flex-col h-[65vh] lg:h-full bg-gray-900 border border-gray-800 rounded-xl overflow-hidden"
      onClick={() => termInputRef.current?.focus()}
    >
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950">
        <span className="text-xs font-mono text-gray-400">Shell · project root</span>
        <div className="flex items-center gap-3">
          <button
            onClick={handleCopy}
            disabled={termLogs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Copy all output to clipboard"
          >
            {copied ? <CheckCheck size={12} /> : <Copy size={12} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button
            onClick={() => downloadText(`terminal-${Date.now()}.txt`, termLogs.map((e) => e.text).join('\n'))}
            disabled={termLogs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Download output"
          >
            <Download size={12} /> Download
          </button>
          <button onClick={() => setTermLogs([])} className="text-xs text-gray-600 hover:text-gray-400">Clear</button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-0.5 [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70 [&::-webkit-scrollbar-corner]:bg-gray-900">
        {termLogs.length === 0 && (
          <div className="text-gray-600 italic">Type a command below and press Enter...</div>
        )}
        {termLogs.map((e, i) => (
          <div key={i} className={
            e.type === 'error' ? 'text-red-400' :
            e.type === 'start' ? 'text-orange-300 font-semibold' :
            e.type === 'done'  ? 'text-green-400' :
            'text-gray-200'
          }>{e.text}</div>
        ))}
        {termRunning && <div className="text-gray-500 animate-pulse">...</div>}
        <div ref={termEndRef} />
      </div>
      <div className="border-t border-gray-800 px-4 py-2 flex items-center gap-2 bg-gray-950">
        <span className="text-orange-400 font-mono text-sm">$</span>
        <input
          ref={termInputRef}
          type="text"
          value={termInput}
          onChange={(e) => { setTermInput(e.target.value); setHistoryIdx(-1); }}
          onKeyDown={handleTermKey}
          disabled={termRunning}
          placeholder="Enter any shell command..."
          className="flex-1 bg-transparent text-sm font-mono text-gray-100 placeholder-gray-600 focus:outline-none disabled:opacity-40"
          autoFocus
        />
        <button
          onClick={() => execCommand(termInput)}
          disabled={termRunning || !termInput.trim()}
          className="text-xs bg-orange-600 hover:bg-orange-500 text-white px-3 py-1 rounded disabled:opacity-30 transition-colors"
        >
          Run
        </button>
      </div>
    </div>
  );
}
