'use client';
import { useState, useEffect, useRef } from 'react';
import { API_BASE_URL } from '../../../../lib/constants';
import { getAdminToken, downloadText, readJsonSafe, isUpstreamUnavailable } from '../../../../lib/adminHelpers';
import { Download, Pencil, X, Check, RotateCcw, Plus, RefreshCw } from 'lucide-react';

interface HealthResult {
  label: string;
  url: string;
  httpStatus: number;
  status?: string;
  version?: string;
  serviceId?: string;
  error?: string;
  responseMs: number;
}

interface SystemInfo {
  os: Record<string, unknown>;
  node: Record<string, unknown>;
  package: Record<string, unknown>;
  env: Record<string, string>;
  dotenvKeys?: string[];
}

// Known prefixes / exact names for this project's app vars.
// Used as a fallback when dotenvKeys is not yet available (server not restarted).
const APP_VAR_PREFIXES = [
  'PSP_', 'MONGODB_', 'ATLAS_', 'JWT_', 'KMS_', 'AWS_',
  'API_', 'CORS_', 'LOCAL_', 'NEXT_PUBLIC_', 'SEED_',
];
const APP_VAR_EXACT = new Set(['NODE_ENV']);

function isAppVar(key: string, dotenvSet: Set<string>): boolean {
  if (dotenvSet.size > 0) return dotenvSet.has(key);
  return APP_VAR_PREFIXES.some(p => key.startsWith(p)) || APP_VAR_EXACT.has(key);
}

type RestartTarget = 'backend' | 'frontend';

const HEALTH_URL = `${API_BASE_URL}/api/v1/system/health`;

export default function InfoPage() {
  const [sysInfo, setSysInfo] = useState<SystemInfo | null>(null);
  const [sysLoading, setSysLoading] = useState(false);
  const [sysError, setSysError] = useState<string | null>(null);
  const [health, setHealth] = useState<HealthResult | null>(null);
  const [envFilter, setEnvFilter] = useState('');
  const [restartRequired, setRestartRequired] = useState(false);
  const [addingVar, setAddingVar] = useState(false);
  const [confirmTarget, setConfirmTarget] = useState<RestartTarget | null>(null);
  const [restarting, setRestarting] = useState<RestartTarget | null>(null);
  const [restartStatus, setRestartStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  function handleDownload() {
    if (!sysInfo) return;
    const lines: string[] = [`=== System Info === ${new Date().toISOString()}`, ''];
    const section = (title: string, obj: Record<string, unknown>) => {
      lines.push(`--- ${title} ---`);
      for (const [k, v] of Object.entries(obj)) {
        if (k === 'scripts' && typeof v === 'object' && v !== null) {
          lines.push('scripts:');
          for (const [sk, sv] of Object.entries(v as Record<string, string>)) {
            lines.push(`  ${sk}: ${sv}`);
          }
        } else {
          lines.push(`${k}: ${String(v)}`);
        }
      }
      lines.push('');
    };
    section('Operating System', sysInfo.os);
    section('Node.js Runtime', sysInfo.node);
    section('package.json', sysInfo.package);
    lines.push('--- Environment Variables ---');
    for (const [k, v] of Object.entries(sysInfo.env).sort(([a], [b]) => a.localeCompare(b))) {
      lines.push(`${k}=${v}`);
    }
    downloadText(`system-info-${Date.now()}.txt`, lines.join('\n'));
  }

  async function fetchHealth() {
    const t0 = Date.now();
    try {
      const res = await fetch(HEALTH_URL);
      // The body is not JSON while the backend is down (proxy error page); do not parse blindly.
      const { data, text } = await readJsonSafe<Record<string, unknown>>(res);
      if (!data) {
        setHealth({
          label: '/api/v1/system/health', url: HEALTH_URL, httpStatus: res.status,
          status: isUpstreamUnavailable(res) ? 'restarting' : 'error',
          error: text.trim().slice(0, 120) || res.statusText,
          responseMs: Date.now() - t0,
        });
        return;
      }
      setHealth({ label: '/api/v1/system/health', url: HEALTH_URL, httpStatus: res.status, responseMs: Date.now() - t0, ...data } as HealthResult);
    } catch (err) {
      setHealth({ label: '/api/v1/system/health', url: HEALTH_URL, httpStatus: 0, status: 'error', error: (err as Error).message, responseMs: Date.now() - t0 });
    }
  }

  async function fetchSysInfo() {
    const token = getAdminToken();
    if (!token) return;
    setSysLoading(true);
    setSysError(null);
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/admin/system`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { data, text } = await readJsonSafe<SystemInfo & { error?: string }>(res);
      if (!res.ok) {
        if (isUpstreamUnavailable(res)) throw new Error('Backend unavailable (restarting)');
        throw new Error(data?.error ?? (text.trim().slice(0, 120) || res.statusText));
      }
      if (!data) throw new Error('Unexpected non-JSON response from the backend');
      setSysInfo(data);
    } catch (err) {
      setSysError((err as Error).message);
    } finally {
      setSysLoading(false);
    }
  }

  async function handleEnvSave(key: string, value: string): Promise<void> {
    const token = getAdminToken();
    if (!token) throw new Error('Not authenticated');
    const res = await fetch(`${API_BASE_URL}/api/v1/admin/env`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ key, value }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error((err as { error?: string }).error ?? res.statusText);
    }
    setRestartRequired(true);
    await fetchSysInfo();
  }

  async function restartServer(target: RestartTarget) {
    const token = getAdminToken();
    if (!token) return;
    setConfirmTarget(null);
    setRestarting(target);
    setRestartStatus(null);

    try {
      await fetch(`${API_BASE_URL}/api/v1/admin/restart`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ target }),
      });
    } catch {
      // backend restart triggers a connection reset - this is expected
    }

    if (target === 'backend') {
      setRestartStatus({ ok: false, msg: 'Backend restarting - reconnecting...' });
      let attempts = 0;
      pollRef.current = setInterval(async () => {
        attempts += 1;
        try {
          const res = await fetch(`${API_BASE_URL}/api/v1/admin/system`, {
            headers: { Authorization: `Bearer ${getAdminToken() ?? ''}` },
          });
          // An app-level response (200 or 401) means the server is back. A 502/503/504 comes from
          // the proxy while no pod is reachable, so it must NOT be read as "back online".
          if (isUpstreamUnavailable(res)) throw new Error('upstream down');
          clearInterval(pollRef.current!);
          setRestarting(null);
          setRestartStatus({ ok: true, msg: 'Backend is back online' });
          fetchSysInfo();
          setTimeout(() => setRestartStatus(null), 4000);
        } catch {
          // Still restarting. Give up after ~60s instead of polling forever.
          if (attempts >= 30) {
            clearInterval(pollRef.current!);
            setRestarting(null);
            setRestartStatus({ ok: false, msg: 'Backend did not come back after 60s - check the pod logs' });
          }
        }
      }, 2000);
    }

    if (target === 'frontend') {
      setRestartStatus({ ok: false, msg: 'Frontend restarting - page will reload in ~10s' });
      setTimeout(() => window.location.reload(), 10000);
    }
  }

  useEffect(() => {
    fetchSysInfo();
    fetchHealth();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex flex-col gap-4 lg:h-full">
      <div className="flex-shrink-0 flex items-center gap-3 flex-wrap">
        <button
          onClick={() => { fetchSysInfo(); fetchHealth(); }}
          disabled={sysLoading}
          className="text-xs bg-orange-600 hover:bg-orange-500 text-white px-3 py-1.5 rounded disabled:opacity-40 transition-colors"
        >
          {sysLoading ? 'Refreshing...' : 'Refresh'}
        </button>
        <button
          onClick={handleDownload}
          disabled={!sysInfo}
          className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-300 disabled:opacity-30 transition-colors"
          title="Download summary"
        >
          <Download size={12} /> Download
        </button>

        {/* Server restart controls */}
        <div className="flex items-center gap-2 border-l border-gray-700 pl-3">
          <span className="text-xs text-gray-600 flex-shrink-0">Restart:</span>

          {confirmTarget === 'backend' ? (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-yellow-400">Restart backend?</span>
              <button
                onClick={() => restartServer('backend')}
                className="text-xs text-red-400 hover:text-red-300 px-1.5 py-0.5 rounded border border-red-900/50 hover:border-red-700 transition-colors"
              >
                Yes
              </button>
              <button onClick={() => setConfirmTarget(null)} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">No</button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmTarget('backend')}
              disabled={!!restarting}
              title="Restart backend (tsx watch auto-restarts it)"
              className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-yellow-400 disabled:opacity-30 transition-colors"
            >
              {restarting === 'backend'
                ? <span className="w-3 h-3 border-2 border-yellow-400/30 border-t-yellow-400 rounded-full animate-spin" />
                : <RefreshCw size={11} />
              }
              Backend
            </button>
          )}

          {confirmTarget === 'frontend' ? (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-yellow-400">Restart frontend?</span>
              <button
                onClick={() => restartServer('frontend')}
                className="text-xs text-red-400 hover:text-red-300 px-1.5 py-0.5 rounded border border-red-900/50 hover:border-red-700 transition-colors"
              >
                Yes
              </button>
              <button onClick={() => setConfirmTarget(null)} className="text-xs text-gray-500 hover:text-gray-300 transition-colors">No</button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmTarget('frontend')}
              disabled={!!restarting}
              title="Restart frontend dev server (page reloads automatically)"
              className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-blue-400 disabled:opacity-30 transition-colors"
            >
              {restarting === 'frontend'
                ? <span className="w-3 h-3 border-2 border-blue-400/30 border-t-blue-400 rounded-full animate-spin" />
                : <RefreshCw size={11} />
              }
              Frontend
            </button>
          )}
        </div>

        {sysError && <span className="text-xs text-red-400">{sysError}</span>}
        {restartStatus && (
          <span className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border ${
            restartStatus.ok
              ? 'text-green-400 bg-green-400/10 border-green-400/30'
              : 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
          }`}>
            {!restartStatus.ok && <span className="w-2.5 h-2.5 border-2 border-yellow-400/30 border-t-yellow-400 rounded-full animate-spin" />}
            {restartStatus.msg}
          </span>
        )}
        {!restartStatus && restartRequired && (
          <span className="flex items-center gap-1.5 text-xs text-yellow-400 bg-yellow-400/10 border border-yellow-400/30 px-2.5 py-1 rounded-lg">
            <RotateCcw size={11} />
            Variables updated - restart the server to apply all changes
          </span>
        )}
      </div>

      {sysLoading && !sysInfo && (
        <div className="flex-shrink-0 text-gray-500 text-sm">Loading system info...</div>
      )}

      {sysInfo && (
        <div className="lg:flex-1 lg:min-h-0">
          <div className="grid grid-cols-1 lg:grid-cols-2 lg:grid-rows-[auto_1fr] gap-4 lg:h-full">

            <InfoCard title="Operating System" icon="💻" fixed>
              {Object.entries(sysInfo.os).map(([k, v]) => (
                <InfoRow key={k} label={k} value={String(v)} />
              ))}
            </InfoCard>

            <InfoCard title="Node.js Runtime" icon="🟢" fixed>
              {Object.entries(sysInfo.node).map(([k, v]) => (
                <InfoRow key={k} label={k} value={String(v)} />
              ))}
              {health && (() => {
                const ok = health.httpStatus === 200 && (health.status === 'pass' || health.status === 'ok');
                const degraded = health.httpStatus === 200 && health.status === 'warn';
                const colour = ok ? 'text-green-400' : degraded ? 'text-yellow-400' : 'text-red-400';
                const summary = ok
                  ? `pass · ${health.responseMs}ms`
                  : degraded
                    ? `warn · ${health.responseMs}ms`
                    : health.error
                      ? `${health.error} (${health.responseMs}ms)`
                      : `HTTP ${health.httpStatus} · ${health.responseMs}ms`;
                return (
                  <div className="text-xs py-0.5 border-b border-gray-800/60 flex gap-2 items-center group">
                    <span className="min-w-[140px] flex-shrink-0 text-gray-500 font-mono truncate">/api/v1/system/health</span>
                    <span className={`${colour} flex-1 min-w-0 break-all`}>{summary}</span>
                  </div>
                );
              })()}
              {/* Application versions: shown first, most relevant for quick checks */}
              <InfoRow
                label="backend version"
                value={health?.version ? `v${health.version}`: '—'}
              />
              <InfoRow
                label="frontend version"
                value={`v${process.env.NEXT_PUBLIC_FRONTEND_VERSION ?? '?'}`}
              />
            </InfoCard>

            <InfoCard title="package.json" icon="📦">
              {Object.entries(sysInfo.package).map(([k, v]) =>
                k === 'scripts' ? (
                  <div key={k} className="col-span-2 mt-2">
                    <p className="text-gray-500 text-xs font-semibold uppercase mb-1">scripts</p>
                    {Object.entries(v as Record<string, string>).map(([sk, sv]) => (
                      <div key={sk} className="flex gap-2 text-xs py-0.5 border-b border-gray-800">
                        <code className="text-orange-400 min-w-[120px]">{sk}</code>
                        <code className="text-gray-400 truncate">{sv}</code>
                      </div>
                    ))}
                  </div>
                ) : (
                  <InfoRow key={k} label={k} value={
                    Array.isArray(v) ? (v as string[]).join(', ') : String(v)
                  } />
                )
              )}
            </InfoCard>

            <InfoCard
              title="Environment Variables"
              icon="⚙️"
              subHeader={
                <div className="space-y-2">
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={envFilter}
                      onChange={(e) => setEnvFilter(e.target.value)}
                      placeholder="Filter..."
                      className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-200 placeholder-gray-600 focus:outline-none"
                    />
                    <button
                      onClick={() => setAddingVar(v => !v)}
                      title="Add new variable"
                      className={`flex items-center gap-1 text-xs px-2 py-1 rounded border transition-colors ${
                        addingVar
                          ? 'border-[#00ED64]/60 bg-[#00ED64]/10 text-[#00ED64]'
                          : 'border-gray-700 text-gray-400 hover:border-[#00ED64]/40 hover:text-[#00ED64]'
                      }`}
                    >
                      <Plus size={11} /> Add
                    </button>
                  </div>
                  {addingVar && (
                    <AddVarForm
                      onSave={async (k, v) => { await handleEnvSave(k, v); setAddingVar(false); }}
                      onCancel={() => setAddingVar(false)}
                    />
                  )}
                </div>
              }
            >
              {(() => {
                const dotenvSet = new Set(sysInfo.dotenvKeys ?? []);
                return Object.entries(sysInfo.env)
                  .filter(([k]) => !envFilter || k.toLowerCase().includes(envFilter.toLowerCase()))
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([k, v]) => (
                    <InfoRow
                      key={k}
                      label={k}
                      value={v}
                      mono
                      inDotenv={isAppVar(k, dotenvSet)}
                      onSave={(newVal) => handleEnvSave(k, newVal)}
                    />
                  ));
              })()}
            </InfoCard>
          </div>
        </div>
      )}
    </div>
  );
}

function InfoCard({ title, icon, children, fixed, subHeader }: {
  title: string;
  icon: string;
  children: React.ReactNode;
  fixed?: boolean;
  subHeader?: React.ReactNode;
}) {
  return (
    <div className={`bg-gray-900 border border-gray-800 rounded-xl p-4 flex flex-col${fixed ? '' : ' lg:h-full lg:min-h-0'}`}>
      <p className="flex-shrink-0 text-sm font-semibold text-white mb-3 flex items-center gap-2">
        <span>{icon}</span> {title}
      </p>
      {subHeader && <div className="flex-shrink-0 mb-2">{subHeader}</div>}
      <div className={`space-y-0.5 overflow-y-auto pr-1.5 max-h-64 [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70 [&::-webkit-scrollbar-corner]:bg-gray-900${fixed ? '' : ' lg:max-h-none lg:flex-1 lg:min-h-0'}`}>{children}</div>
    </div>
  );
}

function AddVarForm({ onSave, onCancel }: {
  onSave: (key: string, value: string) => Promise<void>;
  onCancel: () => void;
}) {
  const [key, setKey] = useState('');
  const [value, setValue] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const keyRef = useRef<HTMLInputElement>(null);

  useEffect(() => { keyRef.current?.focus(); }, []);

  async function handleSubmit() {
    const trimmedKey = key.trim().toUpperCase();
    if (!trimmedKey) { setError('Key is required'); return; }
    if (!/^[A-Z_][A-Z0-9_]*$/.test(trimmedKey)) { setError('Key must contain only letters, digits, and underscores'); return; }
    setSaving(true);
    setError(null);
    try {
      await onSave(trimmedKey, value);
    } catch (e) {
      setError((e as Error).message ?? 'Failed to save');
      setSaving(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') onCancel();
  }

  return (
    <div className="bg-gray-800/60 border border-[#00ED64]/20 rounded-lg p-2.5 space-y-2">
      <p className="text-[10px] text-gray-500 uppercase tracking-wide font-semibold">New variable</p>
      <div className="flex gap-1.5 items-center">
        <input
          ref={keyRef}
          type="text"
          value={key}
          onChange={e => { setKey(e.target.value.toUpperCase()); setError(null); }}
          onKeyDown={handleKeyDown}
          placeholder="KEY_NAME"
          className="w-[140px] flex-shrink-0 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-[#00ED64]/50 uppercase"
        />
        <span className="text-gray-600 flex-shrink-0">=</span>
        <input
          type="text"
          value={value}
          onChange={e => setValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleSubmit(); if (e.key === 'Escape') onCancel(); }}
          placeholder="value"
          className="flex-1 min-w-0 bg-gray-900 border border-gray-700 rounded px-2 py-1 text-xs font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-[#00ED64]/50"
        />
        <button
          onClick={handleSubmit}
          disabled={saving}
          className="flex-shrink-0 flex items-center gap-1 text-xs px-2 py-1 rounded bg-[#00ED64]/20 text-[#00ED64] hover:bg-[#00ED64]/30 disabled:opacity-40 transition-colors"
        >
          {saving ? '…' : <><Check size={11} /> Add</>}
        </button>
        <button onClick={onCancel} className="flex-shrink-0 text-gray-600 hover:text-gray-300 transition-colors">
          <X size={13} />
        </button>
      </div>
      {error && <p className="text-red-400 text-[10px]">{error}</p>}
    </div>
  );
}

function InfoRow({ label, value, mono, inDotenv, onSave }: {
  label: string;
  value: string;
  mono?: boolean;
  inDotenv?: boolean;
  onSave?: (v: string) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const isMasked = value === '***' || value.includes('***');

  function startEdit() {
    setDraft(isMasked ? '' : value);
    setSaveError(null);
    setSaved(false);
    setEditing(true);
    setTimeout(() => inputRef.current?.focus(), 0);
  }

  function cancelEdit() {
    setEditing(false);
    setSaveError(null);
  }

  async function commitEdit() {
    if (isMasked && !draft.trim()) { cancelEdit(); return; }
    if (!isMasked && draft === value) { cancelEdit(); return; }
    setSaving(true);
    setSaveError(null);
    try {
      await onSave?.(draft);
      setSaved(true);
      setEditing(false);
    } catch (e) {
      setSaveError((e as Error).message ?? 'Failed to save');
    } finally {
      setSaving(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Enter')  { e.preventDefault(); commitEdit(); }
    if (e.key === 'Escape') { e.preventDefault(); cancelEdit(); }
  }

  return (
    <div className="text-xs py-0.5 border-b border-gray-800/60">
      {editing ? (
        <div className="flex flex-col gap-1 py-0.5">
          <div className="flex items-center gap-1.5">
            <span className={`min-w-[140px] flex-shrink-0 font-mono font-medium truncate ${inDotenv ? 'text-orange-400' : 'text-gray-400'}`} title={label}>{label}</span>
            <input
              ref={inputRef}
              type="text"
              value={draft}
              onChange={e => setDraft(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={isMasked ? 'Enter new value…' : undefined}
              className="flex-1 bg-gray-800 border border-[#00ED64]/50 rounded px-2 py-0.5 font-mono text-gray-100 focus:outline-none focus:border-[#00ED64] min-w-0"
            />
            <button
              onClick={commitEdit}
              disabled={saving}
              title="Save (Enter)"
              className="flex-shrink-0 text-[#00ED64] hover:text-white disabled:opacity-40 transition-colors"
            >
              {saving ? <span className="animate-pulse text-[10px]">…</span> : <Check size={13} />}
            </button>
            <button
              onClick={cancelEdit}
              title="Cancel (Escape)"
              className="flex-shrink-0 text-gray-600 hover:text-gray-300 transition-colors"
            >
              <X size={13} />
            </button>
          </div>
          {isMasked && (
            <p className="text-gray-600 text-[10px] ml-[148px]">Sensitive - leave blank to cancel without saving.</p>
          )}
          {saveError && <p className="text-red-400 text-[10px] ml-[148px]">{saveError}</p>}
        </div>
      ) : (
        <div className="flex gap-2 items-center group">
          <span className={`min-w-[140px] flex-shrink-0 flex items-center gap-1 ${inDotenv ? 'text-orange-400' : 'text-gray-500'}`}>
            {label}
          </span>
          <span className={`${mono ? 'font-mono' : ''} text-gray-300 break-all flex-1 min-w-0`}>{value}</span>
          <div className="flex-shrink-0 flex items-center gap-1.5">
            {saved && (
              <span className="text-[10px] text-yellow-400 flex items-center gap-0.5">
                <RotateCcw size={9} /> restart
              </span>
            )}
            {inDotenv && (
              <button
                onClick={startEdit}
                title="Edit"
                className="text-gray-600 hover:text-orange-400 transition-colors"
              >
                <Pencil size={11} />
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
