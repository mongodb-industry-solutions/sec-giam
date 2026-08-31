'use client';
import { useState, useEffect, useRef, useCallback } from 'react';
import { API_BASE_URL, BACKEND_PUBLIC_URL } from '../../../../lib/constants';
import { getAdminToken, readSSE, downloadText } from '../../../../lib/adminHelpers';
import { Pagination } from '../../../../components/Pagination';
import { JsonView } from '../../../../components/json/JsonView';
import {
  Copy, Check, Trash2, Download, X, ChevronDown, ChevronUp,
  Wifi, WifiOff, RotateCcw,
} from 'lucide-react';

interface WebhookEntry {
  id: string;
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: unknown;
  timestamp: string;
  ip: string;
  // The response the hook sent back to the caller. Optional for backward
  // compatibility with entries persisted before this field existed.
  response?: { status: number; body: unknown };
}

const METHOD_COLORS: Record<string, string> = {
  GET:     'bg-blue-900/60 text-blue-300 border-blue-700',
  POST:    'bg-green-900/60 text-green-300 border-green-700',
  PUT:     'bg-yellow-900/60 text-yellow-300 border-yellow-700',
  PATCH:   'bg-orange-900/60 text-orange-300 border-orange-700',
  DELETE:  'bg-red-900/60 text-red-300 border-red-700',
  OPTIONS: 'bg-gray-700/60 text-gray-300 border-gray-600',
  HEAD:    'bg-gray-700/60 text-gray-300 border-gray-600',
};

const DEFAULT_PAGE_SIZE = 10;
const LIMIT_OPTIONS = [5, 10, 20, 50, 80, 100];
const STORAGE_KEY = 'webhook_inspector_entries';

function bodyText(body: unknown): string {
  if (body === null || body === undefined) return '';
  if (typeof body === 'string') return body;
  return JSON.stringify(body, null, 2);
}

export default function WebhookPage() {
  const [entries, setEntries] = useState<WebhookEntry[]>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? (JSON.parse(raw) as WebhookEntry[]) : [];
    } catch { return []; }
  });
  const [connected, setConnected] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'body' | 'response'>('overview');
  const [filterMethod, setFilterMethod] = useState('');
  const [searchText, setSearchText] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [copied, setCopied] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const hookUrl = `${BACKEND_PUBLIC_URL}/api/v1/admin/webhook/hook`;

  const connect = useCallback(async (token: string) => {
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setConnected(false);
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/admin/webhook/stream`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: ctrl.signal,
      });
      if (!res.ok || !res.body) return;
      setConnected(true);
      await readSSE(res, (type, text) => {
        if (type === 'request') {
          try {
            const entry: WebhookEntry = JSON.parse(text);
            setEntries((prev) => {
              const exists = prev.some((e) => e.id === entry.id);
              return exists ? prev : [entry, ...prev];
            });
          } catch { /* malformed */ }
        } else if (type === 'clear') {
          setEntries([]);
          setExpanded(null);
          setPage(1);
        } else if (type === 'delete') {
          setEntries((prev) => prev.filter((e) => e.id !== text));
          setExpanded((prev) => (prev === text ? null : prev));
        }
      });
    } catch { /* aborted or disconnected */ }
    setConnected(false);
  }, []);

  useEffect(() => {
    const token = getAdminToken();
    if (!token) return;
    connect(token);
    return () => abortRef.current?.abort();
  }, [connect]);

  useEffect(() => {
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => {
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(entries)); } catch { /* quota */ }
    }, 400);
    return () => { if (saveTimer.current) clearTimeout(saveTimer.current); };
  }, [entries]);

  async function clearAll() {
    const token = getAdminToken();
    if (!token) return;
    await fetch(`${API_BASE_URL}/api/v1/admin/webhook/requests`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  async function deleteOne(id: string) {
    const token = getAdminToken();
    if (!token) return;
    await fetch(`${API_BASE_URL}/api/v1/admin/webhook/requests/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
  }

  function copyHookUrl() {
    navigator.clipboard.writeText(hookUrl).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function exportAll() {
    const data = filtered.map(({ headers: _h, ...rest }) => ({ ...rest, headers: _h }));
    downloadText(`webhook-requests-${Date.now()}.json`, JSON.stringify(data, null, 2));
  }

  function exportOne(entry: WebhookEntry) {
    downloadText(`webhook-${entry.id}.json`, JSON.stringify(entry, null, 2));
  }

  const filtered = entries.filter((e) => {
    if (filterMethod && e.method !== filterMethod) return false;
    if (searchText) {
      const q = searchText.toLowerCase();
      const inPath = e.path.toLowerCase().includes(q);
      const inBody = bodyText(e.body).toLowerCase().includes(q);
      if (!inPath && !inBody) return false;
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageEntries = filtered.slice((page - 1) * pageSize, page * pageSize);
  const uniqueMethods = [...new Set(entries.map((e) => e.method))].sort();

  const expandedEntry = entries.find((e) => e.id === expanded) ?? null;

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* Hook URL bar */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl px-4 py-3 flex items-center gap-3 flex-wrap">
        <span className="text-xs text-gray-500 shrink-0">Hook URL</span>
        <code className="flex-1 text-xs text-orange-300 font-mono truncate">{hookUrl}</code>
        <button
          onClick={copyHookUrl}
          className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200 transition-colors shrink-0"
        >
          {copied ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
          {copied ? 'Copied' : 'Copy'}
        </button>
        <span className={`inline-flex items-center gap-1.5 text-xs shrink-0 ${connected ? 'text-green-400' : 'text-gray-600'}`}>
          {connected
            ? <><span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" /><Wifi size={12} /> Live</>
            : <><WifiOff size={12} /> Disconnected</>
          }
        </span>
        {!connected && (
          <button
            onClick={() => { const t = getAdminToken(); if (t) connect(t); }}
            className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            <RotateCcw size={12} /> Reconnect
          </button>
        )}
      </div>

      {/* Filter + actions bar */}
      <div className="flex gap-2 flex-wrap items-center">
        <select
          value={filterMethod}
          onChange={(e) => { setFilterMethod(e.target.value); setPage(1); }}
          className="border border-gray-700 rounded-lg px-3 py-1.5 text-xs bg-gray-900 text-gray-300"
        >
          <option value="">All methods</option>
          {uniqueMethods.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <input
          type="text"
          value={searchText}
          onChange={(e) => { setSearchText(e.target.value); setPage(1); }}
          placeholder="Search path or body…"
          className="flex-1 min-w-[160px] border border-gray-700 rounded-lg px-3 py-1.5 text-xs bg-gray-900 text-gray-300 placeholder-gray-600"
        />
        {(filterMethod || searchText) && (
          <button
            onClick={() => { setFilterMethod(''); setSearchText(''); setPage(1); }}
            className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300"
          >
            <X size={12} /> Clear
          </button>
        )}
        <span className="text-xs text-gray-600 ml-auto">{filtered.length} request{filtered.length !== 1 ? 's' : ''}</span>
        <button
          onClick={exportAll}
          disabled={filtered.length === 0}
          className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-300 disabled:opacity-30 transition-colors"
        >
          <Download size={12} /> Export
        </button>
        <button
          onClick={clearAll}
          disabled={entries.length === 0}
          className="inline-flex items-center gap-1 text-xs text-red-700 hover:text-red-400 disabled:opacity-30 transition-colors"
        >
          <Trash2 size={12} /> Clear all
        </button>
      </div>

      {/* List */}
      {entries.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center py-12 bg-gray-900 border border-gray-800 rounded-xl gap-3">
          <Wifi size={28} className="text-gray-700" />
          <p className="text-gray-500 text-sm">Waiting for requests…</p>
          <p className="text-gray-600 text-xs">Send a request to the hook URL above</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {pageEntries.map((entry) => {
            const isOpen = expanded === entry.id;
            const methodColor = METHOD_COLORS[entry.method] ?? 'bg-gray-700/60 text-gray-300 border-gray-600';
            return (
              <div key={entry.id} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                {/* Row */}
                <div
                  className="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-gray-800/50 transition-colors"
                  onClick={() => { setExpanded(isOpen ? null : entry.id); setActiveTab('overview'); }}
                >
                  <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border shrink-0 ${methodColor}`}>
                    {entry.method}
                  </span>
                  <span className="flex-1 font-mono text-xs text-gray-300 truncate">{entry.path}</span>
                  <span className="text-xs text-gray-600 shrink-0 hidden sm:block">
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="text-xs text-gray-700 shrink-0 hidden md:block font-mono">{entry.ip}</span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={(ev) => { ev.stopPropagation(); exportOne(entry); }}
                      className="text-gray-700 hover:text-gray-400 transition-colors"
                      title="Export JSON"
                    >
                      <Download size={13} />
                    </button>
                    <button
                      onClick={(ev) => { ev.stopPropagation(); deleteOne(entry.id); }}
                      className="text-gray-700 hover:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <Trash2 size={13} />
                    </button>
                    {isOpen ? <ChevronUp size={14} className="text-gray-600" /> : <ChevronDown size={14} className="text-gray-600" />}
                  </div>
                </div>

                {/* Detail panel */}
                {isOpen && expandedEntry && (
                  <div className="border-t border-gray-800">
                    {/* Tabs */}
                    <div className="flex gap-0 border-b border-gray-800 px-4">
                      {(['overview', 'headers', 'body', 'response'] as const).map((tab) => (
                        <button
                          key={tab}
                          onClick={() => setActiveTab(tab)}
                          className={`px-3 py-1.5 text-xs font-medium capitalize transition-colors border-b-2 -mb-px ${
                            activeTab === tab
                              ? 'border-orange-400 text-orange-400'
                              : 'border-transparent text-gray-500 hover:text-gray-300'
                          }`}
                        >
                          {tab}
                        </button>
                      ))}
                    </div>

                    <div className="p-4 font-mono text-xs text-gray-300 overflow-x-auto max-h-72 overflow-y-auto [scrollbar-width:thin] [scrollbar-color:#4b5563_#111827]">
                      {activeTab === 'overview' && (
                        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
                          {[
                            ['ID',        expandedEntry.id],
                            ['Method',    expandedEntry.method],
                            ['Path',      expandedEntry.path],
                            ['IP',        expandedEntry.ip],
                            ['Timestamp', expandedEntry.timestamp],
                          ].map(([k, v]) => (
                            <span key={k} className="contents">
                              <dt className="text-gray-500">{k}</dt>
                              <dd className="text-gray-200 break-all">{v}</dd>
                            </span>
                          ))}
                          {Object.keys(expandedEntry.query).length > 0 && (
                            <span className="contents">
                              <dt className="text-gray-500">Query</dt>
                              <dd className="text-gray-200 break-all">
                                {new URLSearchParams(expandedEntry.query).toString()}
                              </dd>
                            </span>
                          )}
                        </dl>
                      )}

                      {activeTab === 'headers' && (
                        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                          {Object.entries(expandedEntry.headers).map(([k, v]) => (
                            <span key={k} className="contents">
                              <dt className="text-gray-500 whitespace-nowrap">{k}</dt>
                              <dd className="text-gray-200 break-all">{v}</dd>
                            </span>
                          ))}
                        </dl>
                      )}

                      {activeTab === 'body' && (
                        expandedEntry.body
                          ? <JsonView data={expandedEntry.body} theme="dark" surfaceClassName="bg-gray-950 border-gray-800" maxHeight="18rem" />
                          : <span className="text-gray-600 italic">No body</span>
                      )}

                      {activeTab === 'response' && (
                        expandedEntry.response ? (
                          <div className="space-y-3">
                            <div className="flex items-center gap-2">
                              <span className="text-gray-500">Status</span>
                              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
                                expandedEntry.response.status < 300
                                  ? 'bg-green-900/60 text-green-300 border-green-700'
                                  : expandedEntry.response.status < 500
                                    ? 'bg-yellow-900/60 text-yellow-300 border-yellow-700'
                                    : 'bg-red-900/60 text-red-300 border-red-700'
                              }`}>
                                {expandedEntry.response.status}
                              </span>
                            </div>
                            <div>
                              <p className="text-gray-500 mb-1">Body sent to caller</p>
                              {expandedEntry.response.body
                                ? <JsonView data={expandedEntry.response.body} theme="dark" surfaceClassName="bg-gray-950 border-gray-800" maxHeight="14rem" />
                                : <span className="text-gray-600 italic">No body</span>}
                            </div>
                          </div>
                        ) : (
                          <span className="text-gray-600 italic">Response not recorded for this request.</span>
                        )
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          <div ref={bottomRef} />

          <Pagination
            page={page}
            totalPages={totalPages}
            total={filtered.length}
            limit={pageSize}
            onPageChange={(p) => { setPage(p); window.scrollTo({ top: 0, behavior: 'smooth' }); }}
            onLimitChange={(ps) => { setPageSize(ps); setPage(1); }}
            limitOptions={LIMIT_OPTIONS}
            noun="requests"
            variant="dark"
          />
        </div>
      )}
    </div>
  );
}
