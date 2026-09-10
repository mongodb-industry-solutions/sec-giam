'use client';

import { useEffect, useMemo, useState } from 'react';
import { Plus, RefreshCw, Save, Trash2 } from 'lucide-react';
import { API_BASE_URL, SIMULATOR_REALM } from '../../../../lib/constants';
import { getAdminToken, readJsonSafe } from '../../../../lib/adminHelpers';
import {
  type CatalogResourceDraft, type ResourceServerResponse, type ServerDraft,
  draftFromResponse, draftToRegisterBody, emptyServerDraft, serializeDraft,
} from '../../../system/resources/shared';

/**
 * Registering and editing a resource server's own catalog, from the console.
 *
 * DELIBERATE EXCEPTION. Everywhere else in this authority, "the application ships its enforcement
 * points in its own code and PUTs them here, because only the code containing a guard can say the
 * permission exists" (resource.controller.ts) — a role can only ever CHECK a resource:action that
 * already exists, never invent one, and that is the whole reason a permission on a role means
 * anything. This page is the one place that principle is set aside on purpose, for operator
 * convenience in a demo/admin context: it lets a human type a resource and an action here with no
 * code-level guarantee anything actually enforces it. Do not copy this pattern elsewhere; the read
 * side (/system/resources) is what the rest of the console should look like.
 *
 * The endpoint underneath, PUT /admin/resource-servers/:name/permissions, is documented at exactly
 * that bare path (docs/issuer-contract.md), not under /api/v1/admin like this panel's other tabs —
 * a pre-existing inconsistency kept as-is rather than silently changed, since other deployments may
 * already call it at that address.
 */

export default function ResourcesAdminPage() {
  const [realm, setRealm] = useState(SIMULATOR_REALM);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState<ServerDraft[]>([]);
  const [drafts, setDrafts] = useState<ServerDraft[]>([]);
  const [adding, setAdding] = useState(false);
  const [newServer, setNewServer] = useState<ServerDraft>(emptyServerDraft());
  const [busyName, setBusyName] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    const token = getAdminToken();
    if (!token) { setError('Not authenticated.'); return; }
    setLoading(true);
    setError(null);
    try {
      // Bare /admin/..., not /api/v1/admin/...: see the module docstring above.
      const res = await fetch(`${API_BASE_URL}/admin/resource-servers?realm=${encodeURIComponent(realm)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const { data, text } = await readJsonSafe<{ resourceServers: ResourceServerResponse[] }>(res);
      if (!res.ok || !data) throw new Error(text.trim().slice(0, 200) || res.statusText);
      const asDrafts = data.resourceServers.map(draftFromResponse);
      setLoaded(asDrafts);
      setDrafts(asDrafts);
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function updateDraft(index: number, patch: Partial<ServerDraft>) {
    setDrafts((current) => current.map((server, i) => (i === index ? { ...server, ...patch } : server)));
  }

  function updateResourceRow(serverIndex: number, rowIndex: number, patch: Partial<CatalogResourceDraft>) {
    setDrafts((current) => current.map((server, i) => (i !== serverIndex ? server : {
      ...server,
      resources: server.resources.map((row, r) => (r === rowIndex ? { ...row, ...patch } : row)),
    })));
  }

  function addResourceRow(serverIndex: number) {
    setDrafts((current) => current.map((server, i) => (i !== serverIndex ? server : {
      ...server, resources: [...server.resources, { name: '', actionsText: '' }],
    })));
  }

  function removeResourceRow(serverIndex: number, rowIndex: number) {
    setDrafts((current) => current.map((server, i) => (i !== serverIndex ? server : {
      ...server, resources: server.resources.filter((_, r) => r !== rowIndex),
    })));
  }

  async function register(draft: ServerDraft) {
    const token = getAdminToken();
    if (!token) { setError('Not authenticated.'); return; }
    setBusyName(draft.name);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch(`${API_BASE_URL}/admin/resource-servers/${encodeURIComponent(draft.name)}/permissions`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ realm, ...draftToRegisterBody(draft) }),
      });
      const { data, text } = await readJsonSafe<{ registered: number; deprecated: number }>(res);
      if (!res.ok || !data) throw new Error(text.trim().slice(0, 200) || res.statusText);
      setNotice(`${draft.name}: ${data.registered} permission(s) registered, ${data.deprecated} withdrawn.`);
      if (draft === newServer) { setAdding(false); setNewServer(emptyServerDraft()); }
      await load();
    } catch (failure) {
      setError((failure as Error).message);
    } finally {
      setBusyName(null);
    }
  }

  return (
    <div className="space-y-4 text-gray-200">
      <div className="rounded-lg border border-amber-800 bg-amber-950/40 p-3 text-xs text-amber-300">
        This tab lets you type a resource and an action with no code behind it to enforce them. It
        exists for operator convenience in this demo, deliberately against the rule the rest of the
        authority follows (a permission must come from the code that guards it). See{' '}
        <code>/system/resources</code> for the read-only view everything else in the console follows.
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-500">Realm</span>
          <input
            value={realm}
            onChange={(e) => setRealm(e.target.value)}
            className="mt-1 block h-9 rounded-lg border border-gray-700 bg-gray-900 px-2.5 text-sm text-gray-200 focus:border-gray-500 focus:outline-none"
          />
        </label>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading}
          className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-gray-700 px-3 text-xs font-medium text-gray-300 hover:bg-gray-800 disabled:opacity-50"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin' : ''} aria-hidden />
          {loading ? 'Reading…' : 'Reload'}
        </button>
        {!adding && (
          <button
            type="button"
            onClick={() => setAdding(true)}
            className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-emerald-700 px-3 text-xs font-medium text-white hover:bg-emerald-600"
          >
            <Plus size={12} aria-hidden />
            Register a new resource server
          </button>
        )}
      </div>

      {error && <div className="rounded-lg border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">{error}</div>}
      {notice && <div className="rounded-lg border border-emerald-800 bg-emerald-950/40 p-3 text-xs text-emerald-300">{notice}</div>}

      {adding && (
        <ServerBlock
          draft={newServer}
          isNew
          onChange={(patch) => setNewServer((current) => ({ ...current, ...patch }))}
          onRowChange={(rowIndex, patch) => setNewServer((current) => ({
            ...current, resources: current.resources.map((r, i) => (i === rowIndex ? { ...r, ...patch } : r)),
          }))}
          onAddRow={() => setNewServer((current) => ({ ...current, resources: [...current.resources, { name: '', actionsText: '' }] }))}
          onRemoveRow={(rowIndex) => setNewServer((current) => ({ ...current, resources: current.resources.filter((_, i) => i !== rowIndex) }))}
          onCancel={() => { setAdding(false); setNewServer(emptyServerDraft()); }}
          onRegister={() => void register(newServer)}
          busy={busyName === newServer.name}
        />
      )}

      {drafts.map((draft, index) => (
        <ServerBlock
          key={draft.resourceId ?? draft.name}
          draft={draft}
          original={loaded[index]}
          onChange={(patch) => updateDraft(index, patch)}
          onRowChange={(rowIndex, patch) => updateResourceRow(index, rowIndex, patch)}
          onAddRow={() => addResourceRow(index)}
          onRemoveRow={(rowIndex) => removeResourceRow(index, rowIndex)}
          onRegister={() => void register(draft)}
          busy={busyName === draft.name}
        />
      ))}
    </div>
  );
}

function ServerBlock({ draft, original, isNew, onChange, onRowChange, onAddRow, onRemoveRow, onCancel, onRegister, busy }: {
  draft: ServerDraft;
  original?: ServerDraft;
  isNew?: boolean;
  onChange: (patch: Partial<ServerDraft>) => void;
  onRowChange: (rowIndex: number, patch: Partial<CatalogResourceDraft>) => void;
  onAddRow: () => void;
  onRemoveRow: (rowIndex: number) => void;
  onCancel?: () => void;
  onRegister: () => void;
  busy: boolean;
}) {
  const dirty = useMemo(
    () => isNew || !original || serializeDraft(draft) !== serializeDraft(original),
    [draft, original, isNew],
  );
  const inputClass = 'mt-1 block h-9 w-full rounded-lg border border-gray-700 bg-gray-900 px-2.5 text-sm text-gray-200 focus:border-gray-500 focus:outline-none';

  return (
    <div className="space-y-3 rounded-xl border border-gray-800 bg-gray-950 p-4">
      <div className="flex flex-wrap items-end gap-2">
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-500">Name</span>
          <input value={draft.name} disabled={!isNew} onChange={(e) => onChange({ name: e.target.value })} className={inputClass} />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-500">Audience</span>
          <input value={draft.audience} onChange={(e) => onChange({ audience: e.target.value })} placeholder={draft.name} className={inputClass} />
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-500">Validation mode</span>
          <select value={draft.validationMode} onChange={(e) => onChange({ validationMode: e.target.value })} className={inputClass}>
            <option value="hybrid">hybrid</option>
            <option value="local-jwks">local-jwks</option>
            <option value="introspection">introspection</option>
          </select>
        </label>
        <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-gray-500">Catalog version</span>
          <input
            type="number"
            min={1}
            value={draft.catalogVersion}
            onChange={(e) => onChange({ catalogVersion: Number(e.target.value) || 1 })}
            className={`${inputClass} w-24`}
          />
        </label>
        {draft.status && (
          <span className="mb-1 rounded border border-gray-700 px-1.5 py-1 text-[10px] uppercase tracking-wide text-gray-400">{draft.status}</span>
        )}
      </div>

      <div className="space-y-2">
        <span className="text-[10px] uppercase tracking-wider text-gray-500">Resources and their actions</span>
        {draft.resources.map((row, rowIndex) => (
          <div key={rowIndex} className="flex flex-wrap items-end gap-2">
            <input
              value={row.name}
              onChange={(e) => onRowChange(rowIndex, { name: e.target.value })}
              placeholder="resource"
              className={`${inputClass} w-40 font-mono text-xs`}
            />
            <input
              value={row.actionsText}
              onChange={(e) => onRowChange(rowIndex, { actionsText: e.target.value })}
              placeholder="view, manage"
              className={`${inputClass} flex-1 font-mono text-xs`}
            />
            <button type="button" onClick={() => onRemoveRow(rowIndex)} className="mb-0.5 rounded-lg border border-gray-700 p-2 text-gray-400 hover:bg-gray-800">
              <Trash2 size={12} aria-hidden />
            </button>
          </div>
        ))}
        <button type="button" onClick={onAddRow} className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200">
          <Plus size={11} aria-hidden />
          Add a resource
        </button>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!dirty || busy || !draft.name.trim()}
          onClick={onRegister}
          className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3 py-2 text-xs font-medium text-white hover:bg-emerald-600 disabled:opacity-40"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Registering…' : 'Register'}
        </button>
        {onCancel && (
          <button type="button" onClick={onCancel} className="rounded-lg border border-gray-700 px-3 py-2 text-xs font-medium text-gray-300 hover:bg-gray-800">
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}
