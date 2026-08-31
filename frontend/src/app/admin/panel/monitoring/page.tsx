'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import { API_BASE_URL } from '../../../../lib/constants';
import { JsonView } from '../../../../components/json/JsonView';
import { mergeMonitoringDefaults } from '../../../../lib/monitoringDefaults';
import {
  Activity, Plus, PauseCircle, PlayCircle, Trash2,
  RefreshCw, Power, ChevronDown, ChevronUp, RotateCcw,
  X, Check, AlertCircle,
} from 'lucide-react';

// ── Types ──────────────────────────────────────────────────────────────────

type ServiceType = 'atlas' | 'api' | 'http';

interface MonitoringService {
  id: string;
  name: string;
  description: string;
  type: ServiceType;
  url: string;
  detailUrl?: string;
  method: 'GET' | 'POST';
  enabled: boolean;
  intervalMs: number;
  timeoutMs: number;
  expectedStatus: number;
  useApiBase: boolean;
}

interface CheckResult {
  timestamp: string;
  ok: boolean;
  statusCode: number;
  responseMs: number;
  error?: string;
  meta?: Record<string, unknown>;
}

// ── Storage keys ───────────────────────────────────────────────────────────

const CONFIG_KEY  = 'pci_monitoring_config';
const PAUSED_KEY  = 'pci_monitoring_paused';
// Ids of shipped defaults this browser has already been offered. Without it a newly shipped service
// never appears for anyone who already has a stored config, and re-offering it unconditionally would
// resurrect a service the operator deliberately deleted.
const KNOWN_KEY   = 'pci_monitoring_known_defaults';
const MAX_HISTORY = 20;

function loadConfig(): MonitoringService[] {
  try {
    const raw = localStorage.getItem(CONFIG_KEY);
    if (raw) return JSON.parse(raw) as MonitoringService[];
  } catch { /* ignore */ }
  return [];
}

function saveConfig(services: MonitoringService[]): void {
  try { localStorage.setItem(CONFIG_KEY, JSON.stringify(services)); } catch { /* quota */ }
}

function loadKnownDefaults(): string[] {
  try {
    const raw = localStorage.getItem(KNOWN_KEY);
    if (raw) return JSON.parse(raw) as string[];
  } catch { /* ignore */ }
  return [];
}

function saveKnownDefaults(ids: string[]): void {
  try { localStorage.setItem(KNOWN_KEY, JSON.stringify([...new Set(ids)])); } catch { /* quota */ }
}

function loadPaused(): boolean {
  return localStorage.getItem(PAUSED_KEY) === 'true';
}

function savePaused(v: boolean): void {
  localStorage.setItem(PAUSED_KEY, v ? 'true' : 'false');
}

async function fetchDefaults(): Promise<MonitoringService[]> {
  try {
    const res = await fetch('/monitoring-defaults.json');
    if (!res.ok) return [];
    const data = await res.json() as { services: MonitoringService[] };
    return data.services ?? [];
  } catch { return []; }
}

// ── Check runner ───────────────────────────────────────────────────────────

async function runCheck(service: MonitoringService): Promise<CheckResult> {
  const url = service.useApiBase
    ? `${API_BASE_URL}${service.url}`
    : service.url;
  const t0 = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), service.timeoutMs);
  try {
    const res = await fetch(url, { method: service.method, signal: ctrl.signal });
    clearTimeout(timer);
    const responseMs = Date.now() - t0;
    let meta: Record<string, unknown> | undefined;
    try { meta = await res.json() as Record<string, unknown>; } catch { /* not JSON */ }
    const ok = res.status === service.expectedStatus;
    return { timestamp: new Date().toISOString(), ok, statusCode: res.status, responseMs, meta };
  } catch (err) {
    clearTimeout(timer);
    const isTimeout = err instanceof Error && err.name === 'AbortError';
    return {
      timestamp: new Date().toISOString(),
      ok: false,
      statusCode: 0,
      responseMs: Date.now() - t0,
      error: isTimeout ? 'Timeout' : (err instanceof Error ? err.message : 'Network error'),
    };
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function formatInterval(ms: number): string {
  if (ms < 60000) return `${ms / 1000}s`;
  return `${Math.floor(ms / 60000)}m`;
}

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

// ── Sparkline ──────────────────────────────────────────────────────────────

function Sparkline({ history }: { history: CheckResult[] }) {
  const items = [...history].reverse(); // oldest first
  const maxMs = Math.max(...items.map(r => r.responseMs), 300);
  const slots = Array.from({ length: MAX_HISTORY }, (_, i) => items[i] ?? null);

  return (
    <div className="flex items-end gap-px h-5" aria-hidden>
      {slots.map((r, i) => {
        if (!r) {
          return <div key={i} className="w-1.5 h-1 bg-gray-800 rounded-sm flex-shrink-0" />;
        }
        const heightPct = Math.max(18, Math.min(100, (r.responseMs / maxMs) * 100));
        return (
          <div
            key={i}
            style={{ height: `${heightPct}%` }}
            title={`${r.ok ? '✓' : '✗'} ${r.responseMs}ms · ${new Date(r.timestamp).toLocaleTimeString()}`}
            className={`w-1.5 rounded-sm flex-shrink-0 ${r.ok ? 'bg-green-500' : 'bg-red-500'}`}
          />
        );
      })}
    </div>
  );
}

// ── Toggle switch ──────────────────────────────────────────────────────────

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      onClick={onChange}
      className={`relative inline-flex h-4 w-7 flex-shrink-0 items-center rounded-full transition-colors focus:outline-none ${
        on ? 'bg-green-600' : 'bg-gray-700'
      }`}
    >
      <span
        className={`inline-block h-3 w-3 transform rounded-full bg-white shadow transition-transform ${
          on ? 'translate-x-3.5' : 'translate-x-0.5'
        }`}
      />
    </button>
  );
}

// ── Service card ───────────────────────────────────────────────────────────

interface DetailData {
  status: string;
  version?: string;
  serviceId?: string;
  description?: string;
  checks?: Record<string, Array<{ status: string; componentType: string; observedValue?: unknown; observedUnit?: string; output?: string; time?: string }>>;
}

function ServiceCard({
  service, history, checking, paused,
  onToggle, onCheckNow, onRemove,
}: {
  service: MonitoringService;
  history: CheckResult[];
  checking: boolean;
  paused: boolean;
  onToggle: () => void;
  onCheckNow: () => void;
  onRemove: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [detailData, setDetailData] = useState<DetailData | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const last = history[0];
  const isActive = service.enabled && !paused;

  // Status derivation
  let dotClass = 'bg-gray-600';
  let statusLabel = 'Disabled';
  let statusColor = 'text-gray-500';

  if (service.enabled && paused) {
    dotClass = 'bg-yellow-600';
    statusLabel = 'Paused';
    statusColor = 'text-yellow-600';
  } else if (isActive) {
    if (!last) {
      dotClass = 'bg-gray-500 animate-pulse';
      statusLabel = 'Pending…';
      statusColor = 'text-gray-400';
    } else if (last.ok) {
      const ietfStatus = last.meta?.status as string | undefined;
      if (ietfStatus === 'warn') {
        dotClass = 'bg-yellow-500';
        statusLabel = 'Degraded';
        statusColor = 'text-yellow-400';
      } else {
        dotClass = 'bg-green-500';
        statusLabel = 'Healthy';
        statusColor = 'text-green-400';
      }
    } else {
      dotClass = 'bg-red-500 animate-pulse';
      statusLabel = 'Down';
      statusColor = 'text-red-400';
    }
  }

  // Fetch detail data on expand (only if detailUrl is configured)
  useEffect(() => {
    if (!expanded || !service.detailUrl || detailData) return;
    const url = service.useApiBase ? `${API_BASE_URL}${service.detailUrl}` : service.detailUrl;
    setDetailLoading(true);
    fetch(url)
      .then((r) => r.json())
      .then((d) => setDetailData(d as DetailData))
      .catch(() => {})
      .finally(() => setDetailLoading(false));
  }, [expanded, service.detailUrl, service.useApiBase, detailData]);

  const upCount   = history.filter(r => r.ok).length;
  const downCount = history.filter(r => !r.ok).length;
  const uptimePct = history.length > 0
    ? Math.round((upCount / history.length) * 100)
    : null;

  const borderClass = isActive && last?.ok === false
    ? 'border-red-900/50'
    : 'border-gray-800';

  return (
    <div className={`bg-gray-900 border ${borderClass} rounded-xl overflow-hidden transition-colors`}>

      {/* Main row */}
      <div className="px-4 py-3 flex items-center gap-3">
        <div className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${dotClass}`} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-sm font-semibold ${service.enabled ? 'text-white' : 'text-gray-500'}`}>
              {service.name}
            </span>
            <span className={`text-xs ${statusColor}`}>
              {checking ? (
                <span className="flex items-center gap-1">
                  <span className="w-2.5 h-2.5 border border-gray-500 border-t-orange-400 rounded-full animate-spin inline-block" />
                  Checking…
                </span>
              ) : statusLabel}
            </span>
          </div>
          {service.description && (
            <p className="text-xs text-gray-600 truncate mt-0.5">{service.description}</p>
          )}
        </div>

        {/* Response time */}
        {last && isActive && (
          <span className={`text-xs font-mono flex-shrink-0 hidden sm:block ${last.ok ? 'text-gray-500' : 'text-red-500'}`}>
            {last.responseMs}ms
          </span>
        )}

        {/* Interval badge */}
        <span className="text-[11px] text-gray-700 flex-shrink-0 hidden md:block">
          /{formatInterval(service.intervalMs)}
        </span>

        {/* Controls */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={onCheckNow}
            disabled={checking}
            title="Check now"
            className="text-gray-600 hover:text-orange-400 disabled:opacity-30 transition-colors"
          >
            <RefreshCw size={13} className={checking ? 'animate-spin' : ''} />
          </button>
          <Toggle on={service.enabled} onChange={onToggle} />
          {confirmRemove ? (
            <div className="flex items-center gap-1">
              <button
                onClick={() => { setConfirmRemove(false); onRemove(); }}
                className="text-[10px] text-red-400 hover:text-red-300 transition-colors"
              >
                Remove
              </button>
              <button
                onClick={() => setConfirmRemove(false)}
                className="text-gray-600 hover:text-gray-300 transition-colors"
              >
                <X size={11} />
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmRemove(true)}
              title="Remove service"
              className="text-gray-700 hover:text-red-400 transition-colors"
            >
              <Trash2 size={13} />
            </button>
          )}
          <button
            onClick={() => setExpanded(v => !v)}
            className="text-gray-600 hover:text-gray-300 transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
        </div>
      </div>

      {/* Sparkline + uptime row */}
      <div className="px-4 pb-3 flex items-center gap-3">
        <Sparkline history={history} />
        <div className="flex items-center gap-3 ml-auto text-[11px] text-gray-700 font-mono">
          {uptimePct !== null && (
            <span className={uptimePct === 100 ? 'text-green-700' : uptimePct < 80 ? 'text-red-700' : 'text-gray-600'}>
              {uptimePct}%
            </span>
          )}
          <span title="Successful checks">↑{upCount}</span>
          {downCount > 0 && <span className="text-red-700" title="Failed checks">↓{downCount}</span>}
        </div>
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-gray-800 px-4 py-3 space-y-3 max-h-[28rem] overflow-y-auto [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70">

          {/* IETF health checks detail (fetched on-demand) */}
          {detailLoading && (
            <p className="text-xs text-gray-500 animate-pulse">Loading detail…</p>
          )}
          {detailData && detailData.checks && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <p className="text-[10px] text-gray-600 uppercase tracking-wide font-semibold">
                  Component checks
                </p>
                {detailData.version && (
                  <span className="text-[10px] text-gray-700 font-mono">v{detailData.version}</span>
                )}
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                  detailData.status === 'pass' ? 'bg-green-900/30 text-green-400' :
                  detailData.status === 'warn' ? 'bg-yellow-900/30 text-yellow-400' :
                  'bg-red-900/30 text-red-400'
                }`}>
                  {detailData.status}
                </span>
                <button
                  onClick={() => setDetailData(null)}
                  title="Refresh detail"
                  className="ml-auto text-gray-700 hover:text-gray-400 transition-colors"
                >
                  <RefreshCw size={10} />
                </button>
              </div>

              {/* Render each check as a collapsible entry */}
              {Object.entries(detailData.checks).map(([name, entries]) => (
                entries.map((entry, i) => (
                  <div key={`${name}-${i}`} className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`flex-shrink-0 w-2 h-2 rounded-full ${
                        entry.status === 'pass' ? 'bg-green-500' :
                        entry.status === 'warn' ? 'bg-yellow-500' : 'bg-red-500'
                      }`} />
                      <span className="text-xs font-mono text-gray-400">{name}</span>
                      {entry.observedUnit && typeof entry.observedValue !== 'object' && (
                        <span className="text-xs font-mono text-gray-500">
                          {String(entry.observedValue)} {entry.observedUnit}
                        </span>
                      )}
                      {entry.output && (
                        <span className="text-xs font-mono text-red-400 truncate">{entry.output}</span>
                      )}
                    </div>
                    {entry.observedValue !== undefined && typeof entry.observedValue === 'object' && (
                      <JsonView
                        data={entry.observedValue}
                        theme="dark"
                        maxHeight="10rem"
                        collapsed={1}
                        hideToolbar
                        surfaceClassName="bg-gray-950 border-gray-800"
                      />
                    )}
                  </div>
                ))
              ))}
            </div>
          )}

          {/* Fallback: Config when no detailUrl or no data yet */}
          {!detailData && !detailLoading && (
            <div>
              <p className="text-[10px] text-gray-600 uppercase tracking-wide font-semibold mb-1.5">Configuration</p>
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono">
                <dt className="text-gray-500">URL</dt>
                <dd className="text-gray-300 truncate" title={service.useApiBase ? `${API_BASE_URL}${service.url}` : service.url}>
                  {service.useApiBase ? (
                    <><span className="text-gray-600">{API_BASE_URL}</span>{service.url}</>
                  ) : service.url}
                </dd>
                <dt className="text-gray-500">Method</dt>
                <dd className="text-gray-300">{service.method}</dd>
                <dt className="text-gray-500">Expect</dt>
                <dd className="text-gray-300">HTTP {service.expectedStatus}</dd>
                <dt className="text-gray-500">Interval</dt>
                <dd className="text-gray-300">{formatInterval(service.intervalMs)}</dd>
                <dt className="text-gray-500">Timeout</dt>
                <dd className="text-gray-300">{service.timeoutMs / 1000}s</dd>
              </dl>
            </div>
          )}

          {/* Last error */}
          {last?.error && (
            <div className="border-t border-gray-800 pt-3">
              <p className="flex items-start gap-1.5 text-xs text-red-400 font-mono">
                <AlertCircle size={12} className="flex-shrink-0 mt-0.5" />
                {last.error}
              </p>
            </div>
          )}

          {/* Recent history */}
          {history.length > 0 && (
            <div className="border-t border-gray-800 pt-3">
              <p className="text-[10px] text-gray-600 uppercase tracking-wide font-semibold mb-1.5">Recent checks</p>
              <div className="space-y-0.5">
                {history.slice(0, 8).map((r, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs font-mono">
                    <span className={`w-3 flex-shrink-0 ${r.ok ? 'text-green-500' : 'text-red-400'}`}>
                      {r.ok ? '✓' : '✗'}
                    </span>
                    <span className="text-gray-500 flex-shrink-0">
                      {new Date(r.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`flex-shrink-0 ${r.responseMs > 1000 ? 'text-yellow-500' : 'text-gray-400'}`}>
                      {r.responseMs}ms
                    </span>
                    {r.error && (
                      <span className="text-red-400 truncate">{r.error}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Add service form ───────────────────────────────────────────────────────

function AddServiceForm({ onAdd, onCancel, existingIds }: {
  onAdd: (svc: MonitoringService) => void;
  onCancel: () => void;
  existingIds: string[];
}) {
  const [name,           setName]           = useState('');
  const [description,    setDescription]    = useState('');
  const [url,            setUrl]            = useState('');
  const [useApiBase,     setUseApiBase]     = useState(false);
  const [method,         setMethod]         = useState<'GET' | 'POST'>('GET');
  const [intervalMs,     setIntervalMs]     = useState(30000);
  const [timeoutMs,      setTimeoutMs]      = useState(10000);
  const [expectedStatus, setExpectedStatus] = useState(200);
  const [error,          setError]          = useState<string | null>(null);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => { nameRef.current?.focus(); }, []);

  function handleSubmit() {
    const trimName = name.trim();
    const trimUrl  = url.trim();
    if (!trimName)  { setError('Service name is required');                   return; }
    if (!trimUrl)   { setError('URL is required');                            return; }
    const id = slugify(trimName);
    if (!id)        { setError('Name must contain at least one alphanumeric character'); return; }
    if (existingIds.includes(id)) { setError(`A service with id "${id}" already exists`); return; }

    onAdd({
      id,
      name: trimName,
      description: description.trim(),
      type: 'http',
      url: trimUrl,
      method,
      enabled: true,
      intervalMs,
      timeoutMs,
      expectedStatus,
      useApiBase,
    });
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'Escape') onCancel();
  }

  return (
    <div
      className="bg-gray-900 border border-orange-900/40 rounded-xl p-4 space-y-4"
      onKeyDown={handleKeyDown}
    >
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-white flex items-center gap-2">
          <Plus size={14} className="text-orange-400" />
          New monitoring service
        </p>
        <button onClick={onCancel} className="text-gray-600 hover:text-gray-300 transition-colors">
          <X size={14} />
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {/* Name */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">Service name *</label>
          <input
            ref={nameRef}
            type="text"
            value={name}
            onChange={e => { setName(e.target.value); setError(null); }}
            placeholder="My Service"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500/60"
          />
        </div>

        {/* Description */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">Description</label>
          <input
            type="text"
            value={description}
            onChange={e => setDescription(e.target.value)}
            placeholder="Optional"
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500/60"
          />
        </div>

        {/* URL */}
        <div className="sm:col-span-2">
          <label className="block text-xs text-gray-500 mb-1">URL *</label>
          <div className="flex gap-2 items-center">
            <input
              type="text"
              value={url}
              onChange={e => { setUrl(e.target.value); setError(null); }}
              placeholder={useApiBase ? '/api/v1/...' : 'https://example.com/health'}
              className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs font-mono text-gray-200 placeholder-gray-600 focus:outline-none focus:border-orange-500/60"
            />
            <label className="flex items-center gap-1.5 text-xs text-gray-400 whitespace-nowrap cursor-pointer select-none">
              <input
                type="checkbox"
                checked={useApiBase}
                onChange={e => setUseApiBase(e.target.checked)}
                className="accent-orange-500"
              />
              Prepend API base
            </label>
          </div>
          {useApiBase && url && (
            <p className="text-[10px] font-mono text-gray-600 mt-1">
              → <span className="text-gray-500">{API_BASE_URL}</span>{url}
            </p>
          )}
        </div>

        {/* Method */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">HTTP method</label>
          <select
            value={method}
            onChange={e => setMethod(e.target.value as 'GET' | 'POST')}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
          >
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>

        {/* Expected status */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">Expected HTTP status</label>
          <input
            type="number"
            value={expectedStatus}
            onChange={e => setExpectedStatus(Math.max(100, Math.min(599, Number(e.target.value))))}
            min={100}
            max={599}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
          />
        </div>

        {/* Interval */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">Poll interval</label>
          <select
            value={intervalMs}
            onChange={e => setIntervalMs(Number(e.target.value))}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
          >
            <option value={10000}>10 seconds</option>
            <option value={30000}>30 seconds</option>
            <option value={60000}>1 minute</option>
            <option value={300000}>5 minutes</option>
          </select>
        </div>

        {/* Timeout */}
        <div>
          <label className="block text-xs text-gray-500 mb-1">Request timeout</label>
          <select
            value={timeoutMs}
            onChange={e => setTimeoutMs(Number(e.target.value))}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-gray-200 focus:outline-none"
          >
            <option value={5000}>5 seconds</option>
            <option value={10000}>10 seconds</option>
            <option value={15000}>15 seconds</option>
            <option value={30000}>30 seconds</option>
          </select>
        </div>
      </div>

      {error && (
        <p className="flex items-center gap-1.5 text-xs text-red-400">
          <AlertCircle size={12} /> {error}
        </p>
      )}

      <div className="flex items-center gap-2 border-t border-gray-800 pt-3">
        <button
          onClick={handleSubmit}
          className="inline-flex items-center gap-1.5 text-xs bg-orange-600 hover:bg-orange-500 text-white px-3 py-1.5 rounded-lg transition-colors"
        >
          <Check size={12} /> Add service
        </button>
        <button
          onClick={onCancel}
          className="text-xs text-gray-600 hover:text-gray-300 transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function MonitoringPage() {
  const [services,     setServices]     = useState<MonitoringService[]>([]);
  const [history,      setHistory]      = useState<Record<string, CheckResult[]>>({});
  const [paused,       setPaused]       = useState(false);
  const [adding,       setAdding]       = useState(false);
  const [checking,     setChecking]     = useState<Set<string>>(new Set());
  const [initialized,  setInitialized]  = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const timersRef   = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());
  const servicesRef = useRef<MonitoringService[]>([]);
  servicesRef.current = services;

  const doCheck = useCallback(async (service: MonitoringService) => {
    setChecking(prev => new Set([...prev, service.id]));
    try {
      const result = await runCheck(service);
      setHistory(prev => ({
        ...prev,
        [service.id]: [result, ...(prev[service.id] ?? [])].slice(0, MAX_HISTORY),
      }));
    } finally {
      setChecking(prev => { const s = new Set(prev); s.delete(service.id); return s; });
    }
  }, []);

  // Initialize: load from localStorage, then reconcile against the shipped defaults. A service added
  // to monitoring-defaults.json has to reach existing operators, and one whose endpoint MOVED has to
  // stop being reported as unreachable. See lib/monitoringDefaults for the ownership split.
  useEffect(() => {
    const stored = loadConfig();
    setPaused(loadPaused());
    fetchDefaults().then(defaults => {
      const known = loadKnownDefaults();
      const merged = mergeMonitoringDefaults(stored, defaults, known);
      setServices(merged.services);
      if (merged.changed) saveConfig(merged.services);
      saveKnownDefaults([...known, ...merged.defaultIds]);
      setInitialized(true);
    }).catch(() => {
      setServices(stored);
      setInitialized(true);
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Manage polling timers: restart when services or paused state changes
  useEffect(() => {
    if (!initialized) return;
    const timers = timersRef.current;

    timers.forEach(t => clearInterval(t));
    timers.clear();

    if (!paused) {
      services.forEach(service => {
        if (!service.enabled) return;
        doCheck(service);
        const t = setInterval(() => {
          const current = servicesRef.current.find(s => s.id === service.id);
          if (current?.enabled) doCheck(current);
        }, service.intervalMs);
        timers.set(service.id, t);
      });
    }

    return () => {
      timers.forEach(t => clearInterval(t));
      timers.clear();
    };
  }, [services, paused, initialized, doCheck]);

  function updateServices(next: MonitoringService[]) {
    setServices(next);
    saveConfig(next);
  }

  function toggleService(id: string) {
    updateServices(services.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s));
  }

  function removeService(id: string) {
    updateServices(services.filter(s => s.id !== id));
    setHistory(prev => { const n = { ...prev }; delete n[id]; return n; });
  }

  function addService(svc: MonitoringService) {
    updateServices([...services, svc]);
    setAdding(false);
  }

  function togglePaused() {
    const next = !paused;
    setPaused(next);
    savePaused(next);
  }

  async function resetToDefaults() {
    setConfirmReset(false);
    const defaults = await fetchDefaults();
    updateServices(defaults);
    saveKnownDefaults(defaults.map(d => d.id));
    setHistory({});
  }

  const enabledCount = services.filter(s => s.enabled).length;
  const downCount    = services.filter(s => {
    const last = history[s.id]?.[0];
    return s.enabled && !paused && last && !last.ok;
  }).length;

  return (
    <div className="flex flex-col gap-4 h-full overflow-y-auto [scrollbar-width:thin] [scrollbar-color:#00ED64_#111827] [&::-webkit-scrollbar]:w-1.5 [&::-webkit-scrollbar-track]:bg-gray-900 [&::-webkit-scrollbar-track]:rounded-full [&::-webkit-scrollbar-thumb]:bg-[#00ED64]/40 [&::-webkit-scrollbar-thumb]:rounded-full [&::-webkit-scrollbar-thumb:hover]:bg-[#00ED64]/70 pr-1">

      {/* Header controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Activity size={14} className={downCount > 0 ? 'text-red-400' : 'text-green-500'} />
          <span className="text-xs text-gray-400">
            {enabledCount} of {services.length} active
            {downCount > 0 && (
              <span className="ml-1.5 text-red-400 font-medium">· {downCount} down</span>
            )}
          </span>
        </div>

        <div className="ml-auto flex items-center gap-2">
          {/* Reset to defaults */}
          {confirmReset ? (
            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-yellow-400">Reset config?</span>
              <button
                onClick={resetToDefaults}
                className="text-red-400 hover:text-red-300 transition-colors"
              >
                Yes
              </button>
              <button
                onClick={() => setConfirmReset(false)}
                className="text-gray-500 hover:text-gray-300 transition-colors"
              >
                No
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmReset(true)}
              title="Reset to default services"
              className="inline-flex items-center gap-1 text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              <RotateCcw size={12} />
              <span className="hidden sm:inline">Defaults</span>
            </button>
          )}

          {/* Pause / Resume */}
          <button
            onClick={togglePaused}
            className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-colors ${
              paused
                ? 'border-green-700/60 text-green-400 hover:bg-green-900/20'
                : 'border-gray-700 text-gray-400 hover:border-yellow-700/60 hover:text-yellow-400'
            }`}
          >
            {paused
              ? <><PlayCircle size={12} /> Resume all</>
              : <><PauseCircle size={12} /> Pause all</>
            }
          </button>

          {/* Add service */}
          <button
            onClick={() => setAdding(v => !v)}
            className={`inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg transition-colors ${
              adding
                ? 'bg-orange-600/20 text-orange-400 border border-orange-700/60'
                : 'bg-orange-600 hover:bg-orange-500 text-white'
            }`}
          >
            <Plus size={12} />
            <span className="hidden sm:inline">Add service</span>
          </button>
        </div>
      </div>

      {/* Add service form */}
      {adding && (
        <AddServiceForm
          onAdd={addService}
          onCancel={() => setAdding(false)}
          existingIds={services.map(s => s.id)}
        />
      )}

      {/* Paused banner */}
      {paused && (
        <div className="flex items-center gap-2 px-3 py-2 bg-yellow-900/15 border border-yellow-700/30 rounded-lg text-xs text-yellow-500">
          <PauseCircle size={13} className="flex-shrink-0" />
          Monitoring is paused; polling is suspended for all services.
          <button
            onClick={togglePaused}
            className="ml-auto underline underline-offset-2 hover:no-underline transition-all"
          >
            Resume
          </button>
        </div>
      )}

      {/* Down alert */}
      {!paused && downCount > 0 && (
        <div className="flex items-center gap-2 px-3 py-2 bg-red-900/15 border border-red-700/30 rounded-lg text-xs text-red-400">
          <AlertCircle size={13} className="flex-shrink-0" />
          {downCount} service{downCount > 1 ? 's are' : ' is'} currently unreachable.
        </div>
      )}

      {/* Loading */}
      {!initialized && (
        <div className="text-xs text-gray-600 py-2">Loading configuration…</div>
      )}

      {/* Empty state */}
      {initialized && services.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 bg-gray-900 border border-gray-800 rounded-xl gap-3">
          <Activity size={28} className="text-gray-700" />
          <p className="text-gray-500 text-sm">No services configured</p>
          <button
            onClick={() => setAdding(true)}
            className="text-xs text-orange-400 hover:text-orange-300 transition-colors"
          >
            + Add your first service
          </button>
          <button
            onClick={resetToDefaults}
            className="text-xs text-gray-600 hover:text-gray-400 transition-colors flex items-center gap-1"
          >
            <RotateCcw size={11} /> Load defaults
          </button>
        </div>
      )}

      {/* Service grid */}
      {initialized && services.length > 0 && (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
          {services.map(service => (
            <ServiceCard
              key={service.id}
              service={service}
              history={history[service.id] ?? []}
              checking={checking.has(service.id)}
              paused={paused}
              onToggle={() => toggleService(service.id)}
              onCheckNow={() => doCheck(service)}
              onRemove={() => removeService(service.id)}
            />
          ))}
        </div>
      )}

      {/* Legend */}
      {initialized && services.length > 0 && (
        <p className="text-[10px] text-gray-700 flex items-center gap-3 mt-1">
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-3 bg-green-500 rounded-sm inline-block" /> OK
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-3 bg-red-500 rounded-sm inline-block" /> Error
          </span>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1 bg-gray-800 rounded-sm inline-block" /> No data
          </span>
          <span className="ml-1">Bar height = response time (taller = slower)</span>
        </p>
      )}
    </div>
  );
}
