'use client';
import { useState, useRef, useEffect, useSyncExternalStore } from 'react';
import { API_BASE_URL } from '../../../../lib/constants';
import { getAdminToken, readSSE, LogEntry, TestSummary as TestSummaryData, downloadText } from '../../../../lib/adminHelpers';
import { Download, Copy, CheckCheck, CheckCircle2, XCircle, Square } from 'lucide-react';

const SETUP_LOGS_KEY = 'admin_setup_logs';

interface CommandDef {
  id: string;
  label: string;
  description: string;
  icon: string;
  group: 'setup' | 'test' | 'danger';
  confirmMessage?: string;
  confirmLabel?: string;
}

const COMMANDS: CommandDef[] = [
  { id: 'setup',            label: 'Full Setup',        description: 'Install all dependencies (frontend + backend)',    icon: '📦', group: 'setup' },
  { id: 'setup:key:master', label: 'Generate Master Key', description: 'Generate the local KMS master key for Queryable Encryption (KMS_LOCAL_MASTER_KEY)', icon: '🔑', group: 'setup' },
  { id: 'setup:key:rsa',    label: 'Generate RSA Keys', description: 'Generate the RSA OAuth/OIDC signing keypair (private.pem + public.pem)', icon: '🔐', group: 'setup' },
  { id: 'setup:db',         label: 'Setup Database',    description: 'Create collections, indexes, and provision DEKs', icon: '🗄️', group: 'setup' },
  { id: 'setup:generate',   label: 'Generate Data',     description: 'Generate synthetic demo dataset',                  icon: '🎲', group: 'setup' },
  { id: 'setup:seed',       label: 'Seed Database',     description: 'Insert generated data into MongoDB Atlas',         icon: '🌱', group: 'setup' },
  { id: 'setup:check',     label: 'Validate Setup',    description: 'Check env vars, collections, indexes, DEKs, and Atlas roles are provisioned', icon: '✅', group: 'setup' },
  { id: 'reload',           label: 'Reload Runtime',    description: 'Hot-reload .env + QE client + event bus in-process (no restart). Use after Drop + Setup DB + Seed on servers you cannot restart, to pick up the new key vault / DEKs.', icon: '♻️', group: 'setup' },
  { id: 'test',             label: 'All Tests',         description: 'Run unit + integration test suites',                              icon: '🧪', group: 'test'  },
  { id: 'test:unit',        label: 'Unit Tests',        description: 'Run unit tests only',                                             icon: '🔬', group: 'test'  },
  { id: 'test:integration', label: 'Integration Tests', description: 'Run integration tests only',                                      icon: '🔗', group: 'test'  },
  { id: 'test:e2e',         label: 'E2E Tests',         description: 'Run Playwright end-to-end tests (requires live stack on :3000)',   icon: '🎭', group: 'test'  },
  { id: 'type-check',       label: 'Type Check',        description: 'TypeScript type check (no emit)',                                  icon: '📐', group: 'test'  },
  {
    id: 'setup:db:drop',
    label: 'Drop Everything',
    description: 'Drop all collections, key vault, indexes, Atlas roles and DB users',
    icon: '🗑️',
    group: 'danger',
    confirmMessage: 'This will permanently delete all collections, the QE key vault, all indexes, and Atlas custom roles and DB users. All data will be lost. This cannot be undone.',
    confirmLabel: 'Drop Everything',
  },
];

// ---------------------------------------------------------------------------
//  Module-level store: persists across tab switches (mount/unmount)
// ---------------------------------------------------------------------------

interface SetupStore {
  logs: LogEntry[];
  running: boolean;
  activeCommand: string | null;
  commandStatus: null | 'success' | 'failure';
  summary: TestSummaryData | null;
  startedAt: number | null;
}

let _state: SetupStore = {
  logs: (() => {
    if (typeof window === 'undefined') return [];
    try { return JSON.parse(sessionStorage.getItem(SETUP_LOGS_KEY) ?? '[]'); } catch { return []; }
  })(),
  running: false,
  activeCommand: null,
  commandStatus: null,
  summary: null,
  startedAt: null,
};

let _controller: AbortController | null = null;
const _listeners = new Set<() => void>();

function _notify() { _listeners.forEach((fn) => fn()); }

function _update(partial: Partial<SetupStore>) {
  _state = { ..._state, ...partial };
  if (partial.logs !== undefined) {
    if (_state.logs.length === 0) sessionStorage.removeItem(SETUP_LOGS_KEY);
    else sessionStorage.setItem(SETUP_LOGS_KEY, JSON.stringify(_state.logs));
  }
  _notify();
}

function _pushLog(entry: LogEntry) {
  _update({ logs: [..._state.logs, entry] });
}

async function _runCommand(commandId: string) {
  const token = getAdminToken();
  if (_state.running || !token) return;

  _controller = new AbortController();
  _update({
    running: true,
    activeCommand: commandId,
    commandStatus: null,
    summary: null,
    logs: [],
    startedAt: Date.now(),
  });

  // Hot-reload is an in-process action (not a spawned script): plain JSON POST, no SSE stream.
  if (commandId === 'reload') {
    try {
      _pushLog({ type: 'start', text: '$ reload, hot-reload runtime (.env + QE client + event bus), no restart' });
      const res = await fetch(`${API_BASE_URL}/api/v1/admin/reload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({}),
        signal: _controller.signal,
      });
      const body = await res.json().catch(() => ({ error: res.statusText })) as { message?: string; steps?: string[]; error?: string };
      if (res.ok) {
        for (const step of body.steps ?? []) _pushLog({ type: 'log', text: `• ${step}` });
        _pushLog({ type: 'log', text: body.message ?? 'Runtime reloaded.' });
        _pushLog({ type: 'done', text: 'Done, exit code 0' });
        _update({ commandStatus: 'success' });
      } else {
        _pushLog({ type: 'error', text: body.error ?? 'Reload failed' });
        _update({ commandStatus: 'failure' });
      }
    } catch (err: unknown) {
      _pushLog({ type: 'error', text: String(err) });
      _update({ commandStatus: 'failure' });
    } finally {
      _update({ running: false, activeCommand: null });
      _controller = null;
    }
    return;
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/admin/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ command: commandId }),
      signal: _controller.signal,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      _update({
        logs: [{ type: 'error', text: (err as { error?: string }).error ?? 'Request failed' }],
        commandStatus: 'failure',
      });
      return;
    }
    await readSSE(
      res,
      (type, text) => {
        if (type === 'done') {
          const match = /code\s+(\d+)/i.exec(text);
          _update({ commandStatus: match?.[1] === '0' ? 'success' : 'failure' });
        }
        _pushLog({ type: type as LogEntry['type'], text });
      },
      (s) => _update({ summary: s }),
      // 60s of silence means the stream was dropped (the server heartbeats every 15s).
      60_000,
    );
    // A stream that ends without a `done` frame was cut mid-run; do not leave it as "running".
    if (_state.commandStatus === null) {
      _pushLog({ type: 'error', text: 'Stream ended before the command reported an exit code. Check the Logs panel for the final result.' });
      _update({ commandStatus: 'failure' });
    }
  } catch (err: unknown) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      _pushLog({ type: 'error', text: 'Stopped by user' });
      _update({ commandStatus: 'failure' });
    } else {
      _pushLog({ type: 'error', text: String(err) });
      _update({ commandStatus: 'failure' });
    }
  } finally {
    _update({ running: false, activeCommand: null });
    _controller = null;
  }
}

function _stop() {
  _controller?.abort();
}

function _clear() {
  _update({ logs: [], commandStatus: null, summary: null, startedAt: null });
}

function subscribe(cb: () => void) {
  _listeners.add(cb);
  return () => { _listeners.delete(cb); };
}
function getSnapshot() { return _state; }
const serverSnapshot: SetupStore = { logs: [], running: false, activeCommand: null, commandStatus: null, summary: null, startedAt: null };
function getServerSnapshot() { return serverSnapshot; }

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

function formatElapsed(ms: number): string {
  const total = Math.floor(ms / 1000);
  if (total < 60) return `${total}s`;
  return `${Math.floor(total / 60)}m ${String(total % 60).padStart(2, '0')}s`;
}

function formatDuration(ms: number): string {
  if (!ms) return '-';
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${String(Math.round(s % 60)).padStart(2, '0')}s`;
}

function logLineClass(e: LogEntry): string {
  if (e.type === 'error') return 'text-red-400';
  if (e.type === 'start') return 'text-orange-400 font-semibold';
  if (e.type === 'done')  return 'text-green-400 font-semibold';
  const t = e.text;
  if (t.includes('[FAIL]') || /\bFAILED\b/.test(t))         return 'text-red-400';
  if (t.includes('[WARN]'))                                   return 'text-yellow-400';
  if (t.includes('[PASS]') || /\bPASSED\b/.test(t))         return 'text-green-400';
  if (t.includes('[SKIP]'))                                   return 'text-gray-500';
  if (/^\s+\d+\)\s/.test(t))                                 return 'text-red-400';
  if (/\b(Error|AssertionError|SecurityError|TimeoutError|TypeError|ReferenceError)[\s:]/.test(t)) return 'text-red-400';
  if (/[×✘]/.test(t))                                        return 'text-red-400';
  if (/[✓✔]/.test(t))                                        return 'text-green-400';
  return 'text-gray-300';
}

// ---------------------------------------------------------------------------
//  Component
// ---------------------------------------------------------------------------

export default function SetupPage() {
  const state = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  const { logs, running, activeCommand, commandStatus, summary, startedAt } = state;

  const logsEndRef = useRef<HTMLDivElement>(null);
  const [pendingConfirm, setPendingConfirm] = useState<CommandDef | null>(null);
  const [now, setNow] = useState<number>(() => Date.now());

  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, [running]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  function handleRun(id: string) {
    const cmd = COMMANDS.find((c) => c.id === id);
    if (cmd?.confirmMessage) {
      setPendingConfirm(cmd);
      return;
    }
    _runCommand(id);
  }

  const setupCmds  = COMMANDS.filter((c) => c.group === 'setup');
  const testCmds   = COMMANDS.filter((c) => c.group === 'test');
  const dangerCmds = COMMANDS.filter((c) => c.group === 'danger');

  const elapsedMs = startedAt ? Math.max(0, (running ? now : Date.now()) - startedAt) : 0;
  const currentStep =
    [...logs].reverse().find((e) => e.type !== 'done' && e.text.trim())?.text ?? 'Starting…';

  const testSummary = !running && summary ? summary : null;

  return (
    <>
      <div className="flex flex-col lg:flex-row gap-6 lg:h-full">
        {/* Left column - command list */}
        <div className="flex-shrink-0 space-y-4 lg:w-2/5 lg:overflow-y-auto [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-transparent [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/30 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/60">
          <CommandGroup label="Setup" cmds={setupCmds} activeCommand={activeCommand} running={running} onRun={handleRun} />
          <CommandGroup label="Test & Quality" cmds={testCmds} activeCommand={activeCommand} running={running} onRun={handleRun} />
          {dangerCmds.length > 0 && (
            <DangerCommandGroup cmds={dangerCmds} activeCommand={activeCommand} running={running} onRun={handleRun} />
          )}
        </div>
        {/* Right column - test summary (when applicable) + output panel */}
        <div className="min-h-[280px] lg:flex-1 lg:min-h-0 min-w-0 flex flex-col gap-4">
          {testSummary && <TestSummary summary={testSummary} status={commandStatus} />}
          <div className="flex-1 min-h-0">
            <LogPanel
              title={activeCommand ? `npm run ${activeCommand}` : 'Output'}
              logs={logs}
              endRef={logsEndRef}
              status={commandStatus}
              running={running}
              elapsedMs={elapsedMs}
              currentStep={currentStep}
              onClear={_clear}
              onStop={_stop}
              onDownload={() => downloadText(`setup-${activeCommand ?? 'output'}-${Date.now()}.txt`, logs.map((e) => e.text).join('\n'))}
            />
          </div>
        </div>
      </div>

      {pendingConfirm && (
        <ConfirmModal
          cmd={pendingConfirm}
          onConfirm={() => {
            const id = pendingConfirm.id;
            setPendingConfirm(null);
            _runCommand(id);
          }}
          onCancel={() => setPendingConfirm(null)}
        />
      )}
    </>
  );
}

function CommandGroup({ label, cmds, activeCommand, running, onRun }: {
  label: string;
  cmds: CommandDef[];
  activeCommand: string | null;
  running: boolean;
  onRun: (id: string) => void;
}) {
  return (
    <div>
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">{label}</p>
      <div className="space-y-1.5">
        {cmds.map((cmd) => (
          <button
            key={cmd.id}
            onClick={() => onRun(cmd.id)}
            disabled={running}
            className={`w-full text-left flex items-start gap-3 p-3 rounded-lg border transition-all ${
              activeCommand === cmd.id
                ? 'border-orange-500 bg-orange-500/10'
                : 'border-gray-800 bg-gray-900 hover:border-gray-700 hover:bg-gray-800'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            <span className="text-lg mt-0.5">{cmd.icon}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold text-white text-sm">{cmd.label}</span>
                <code className="text-xs text-gray-500 font-mono">npm run {cmd.id}</code>
                {activeCommand === cmd.id && running && (
                  <span className="text-xs text-orange-400 animate-pulse">Running...</span>
                )}
              </div>
              <p className="text-gray-400 text-xs mt-0.5">{cmd.description}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function LogPanel({ title, logs, endRef, onClear, onDownload, onStop, status, running, elapsedMs, currentStep }: {
  title: string;
  logs: LogEntry[];
  endRef: React.RefObject<HTMLDivElement | null>;
  onClear: () => void;
  onDownload: () => void;
  onStop: () => void;
  status: null | 'success' | 'failure';
  running: boolean;
  elapsedMs: number;
  currentStep: string;
}) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    const text = logs.map((e) => (e.type === 'error' ? '[ERR] ' : '') + e.text).join('\n');
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col h-[50vh] lg:h-full">
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-950">
        <span className="text-xs font-mono text-gray-400 truncate">{title}</span>
        <div className="flex items-center gap-3 ml-2 flex-shrink-0">
          {running && (
            <button
              onClick={onStop}
              className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded bg-red-600/20 text-red-400 hover:bg-red-600/30 transition-colors"
              title="Stop running command"
            >
              <Square size={10} /> Stop
            </button>
          )}
          <button
            onClick={handleCopy}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Copy all output to clipboard"
          >
            {copied ? <CheckCheck size={12} /> : <Copy size={12} />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
          <button
            onClick={onDownload}
            disabled={logs.length === 0}
            className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
            title="Download output"
          >
            <Download size={12} /> Download
          </button>
          <button onClick={onClear} className="text-xs text-gray-600 hover:text-gray-400">Clear</button>
        </div>
      </div>
      {(running || (status && elapsedMs > 0)) && (
        <div className="px-4 py-2.5 border-b border-gray-800 bg-gray-950/60">
          <div className="flex items-center justify-between gap-3 mb-1.5">
            <span className="text-xs font-mono text-gray-400 min-w-0 flex-1 flex items-center gap-2">
              {running && (
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#00ED64] animate-pulse flex-shrink-0" />
              )}
              <span className="truncate min-w-0">{running ? currentStep : 'Finished'}</span>
            </span>
            <span className="text-xs font-mono text-gray-500 tabular-nums flex-shrink-0">
              {formatElapsed(elapsedMs)}
            </span>
          </div>
          <div className="relative h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
            {running ? (
              <div className="admin-progress-sweep" />
            ) : (
              <div
                className={`absolute inset-0 rounded-full ${
                  status === 'success' ? 'bg-[#00ED64]' : 'bg-red-500'
                }`}
              />
            )}
          </div>
        </div>
      )}
      {status && (
        <div className={`px-4 py-2 flex items-center gap-2 text-xs font-semibold border-b ${
          status === 'success'
            ? 'bg-green-900/30 border-green-800/50 text-green-400'
            : 'bg-red-900/30 border-red-800/50 text-red-400'
        }`}>
          {status === 'success'
            ? '✓ Command completed successfully (exit code 0)'
            : '✗ Command failed, check output above for details'}
        </div>
      )}
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-0.5 [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70 [&::-webkit-scrollbar-corner]:bg-gray-900">
        {logs.length === 0 && <div className="text-gray-600 italic">Select a command to run...</div>}
        {logs.map((e, i) => (
          <div key={i} className={logLineClass(e)}>
            {e.type === 'error' ? '[ERR] ' : ''}{e.text}
          </div>
        ))}
        <div ref={endRef as React.RefObject<HTMLDivElement>} />
      </div>
    </div>
  );
}

function DangerCommandGroup({ cmds, activeCommand, running, onRun }: {
  cmds: CommandDef[];
  activeCommand: string | null;
  running: boolean;
  onRun: (id: string) => void;
}) {
  return (
    <div>
      <p className="text-xs font-semibold text-red-600 uppercase tracking-wider mb-2">Danger Zone</p>
      <div className="space-y-1.5">
        {cmds.map((cmd) => (
          <button
            key={cmd.id}
            onClick={() => onRun(cmd.id)}
            disabled={running}
            className={`w-full text-left flex items-start gap-3 p-3 rounded-lg border transition-all ${
              activeCommand === cmd.id
                ? 'border-red-500 bg-red-500/10'
                : 'border-red-900/50 bg-gray-900 hover:border-red-700 hover:bg-red-950/30'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
          >
            <span className="text-lg mt-0.5">{cmd.icon}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold text-red-400 text-sm">{cmd.label}</span>
                <code className="text-xs text-gray-500 font-mono">npm run {cmd.id}</code>
                {activeCommand === cmd.id && running && (
                  <span className="text-xs text-orange-400 animate-pulse">Running...</span>
                )}
              </div>
              <p className="text-gray-500 text-xs mt-0.5">{cmd.description}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function StatTile({ label, value, sub, tone }: {
  label: string;
  value: number | string;
  sub: string;
  tone: 'pass' | 'fail' | 'neutral';
}) {
  const valueColor =
    tone === 'fail' ? 'text-red-400' :
    tone === 'pass' ? 'text-[#00ED64]' :
    'text-white';
  return (
    <div className="rounded-lg bg-gray-950 border border-gray-800 px-3 py-2">
      <p className="text-[10px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className={`text-xl font-bold tabular-nums ${valueColor}`}>{value}</p>
      <p className="text-[10px] text-gray-500 mt-0.5 truncate">{sub}</p>
    </div>
  );
}

function TestSummary({ summary, status }: {
  summary: TestSummaryData;
  status: null | 'success' | 'failure';
}) {
  const { tool, total, passed, failed, skipped, durationMs, failures } = summary;
  const ok = failed === 0 && status !== 'failure';

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex-shrink-0">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {ok
            ? <CheckCircle2 size={18} className="text-[#00ED64]" />
            : <XCircle size={18} className="text-red-500" />}
          <h3 className="text-sm font-semibold text-white">Test Results</h3>
          <span className="text-[10px] font-mono uppercase tracking-wider text-gray-500 border border-gray-700 rounded px-1.5 py-0.5">
            {tool === 'all' ? 'all suites' : tool}
          </span>
        </div>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
          ok ? 'bg-[#00ED64]/15 text-[#00ED64]' : 'bg-red-500/15 text-red-400'
        }`}>
          {ok ? 'All passed' : `${failed} failed`}
        </span>
      </div>

      <div className="grid grid-cols-4 gap-2">
        <StatTile label="Tests"    value={total}   sub={`${skipped} skipped`}          tone="neutral" />
        <StatTile label="Passed"   value={passed}  sub="of total"                       tone="pass" />
        <StatTile label="Failed"   value={failed}  sub={failed ? 'see below' : 'none'}  tone={failed ? 'fail' : 'pass'} />
        <StatTile label="Duration" value={formatDuration(durationMs)} sub="wall clock" tone="neutral" />
      </div>

      {failures.length > 0 && (
        <div className="mt-3">
          <p className="text-[10px] font-semibold text-red-400 uppercase tracking-wider mb-1.5">
            Failures ({failures.length})
          </p>
          <div className="space-y-1.5 max-h-48 overflow-y-auto [scrollbar-width:thin] [scrollbar-color:#ef4444_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-thumb]:bg-red-500/40 [&::-webkit-scrollbar-thumb]:rounded-full">
            {failures.map((f, i) => (
              <div key={i} className="rounded-lg border border-red-900/40 bg-red-950/20 px-3 py-2">
                <p className="text-xs font-mono text-red-300 break-all">{f.title}</p>
                {f.reason && (
                  <p className="text-[11px] font-mono text-gray-400 mt-1 break-all">{f.reason}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ConfirmModal({ cmd, onConfirm, onCancel }: {
  cmd: CommandDef;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div
      className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={onCancel}
    >
      <div
        className="bg-gray-900 border border-red-900/60 rounded-xl p-6 max-w-md w-full shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start gap-3 mb-4">
          <span className="text-xl mt-0.5">⚠️</span>
          <div>
            <h2 className="text-white font-bold text-base">Confirm Destructive Operation</h2>
            <p className="text-gray-400 text-xs mt-0.5">This action cannot be undone.</p>
          </div>
        </div>

        <div className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 mb-4">
          <code className="text-red-400 text-xs font-mono">npm run {cmd.id}</code>
        </div>

        <p className="text-gray-300 text-sm mb-6 leading-relaxed">{cmd.confirmMessage}</p>

        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg border border-gray-700 text-gray-300 text-sm hover:border-gray-500 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-700 text-white text-sm font-semibold transition-colors"
          >
            {cmd.confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
}
