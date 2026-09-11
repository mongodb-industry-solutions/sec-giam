'use client';

import { useMemo, useState } from 'react';
import { Plus, Save, Trash2, X } from 'lucide-react';
import { ActionButton } from '../../../components/RecordCard';
import { Field, INPUT } from '../roles/parts';
import { type CatalogResourceDraft, type ServerDraft, serializeDraft } from './shared';

/**
 * One resource server's catalog, editable. `dirty` is a value comparison against what was loaded
 * (`serializeDraft`), same as the Roles and OAuth-application detail pages: Save enables only once
 * something actually changed, never merely because the screen is "in edit mode".
 *
 * Shared by the resource list's own create form and the resource detail page's edit, so the two
 * cannot drift into offering the same write two different ways.
 */
export function ServerForm({ title, draft: initial, original, isNew, busy, onCancel, onSave }: {
  title: string;
  draft: ServerDraft;
  original?: ServerDraft;
  isNew?: boolean;
  busy: boolean;
  onCancel: () => void;
  onSave: (draft: ServerDraft) => void;
}) {
  const [draft, setDraft] = useState(initial);

  const dirty = useMemo(() => isNew || !original || serializeDraft(draft) !== serializeDraft(original), [draft, original, isNew]);

  function updateRow(rowIndex: number, patch: Partial<CatalogResourceDraft>) {
    setDraft((current) => ({
      ...current,
      resources: current.resources.map((row, i) => (i === rowIndex ? { ...row, ...patch } : row)),
    }));
  }

  return (
    <form
      onSubmit={(event) => { event.preventDefault(); onSave(draft); }}
      className="space-y-4 rounded-xl border border-gray-200 bg-white p-4 shadow-sm"
    >
      <div className="flex items-center justify-between">
        <h2 className="font-semibold text-[#001E2B]">{isNew ? title : `Edit ${title}`}</h2>
        <button type="button" onClick={onCancel} aria-label="Cancel" className="text-gray-400 hover:text-gray-700">
          <X size={16} />
        </button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" hint="Identifies this server everywhere it is referenced. Fixed once registered.">
          <input
            required
            disabled={!isNew}
            value={draft.name}
            onChange={(e) => setDraft((current) => ({ ...current, name: e.target.value }))}
            className={INPUT}
          />
        </Field>
        <Field label="Audience" hint="What a token must name in `aud` to be accepted here.">
          <input
            value={draft.audience}
            onChange={(e) => setDraft((current) => ({ ...current, audience: e.target.value }))}
            placeholder={draft.name}
            className={INPUT}
          />
        </Field>
        <Field label="Validation mode">
          <select
            value={draft.validationMode}
            onChange={(e) => setDraft((current) => ({ ...current, validationMode: e.target.value }))}
            className={INPUT}
          >
            <option value="hybrid">hybrid</option>
            <option value="local-jwks">local-jwks</option>
            <option value="introspection">introspection</option>
          </select>
        </Field>
        <Field label="Catalog version">
          <input
            type="number"
            min={1}
            value={draft.catalogVersion}
            onChange={(e) => setDraft((current) => ({ ...current, catalogVersion: Number(e.target.value) || 1 }))}
            className={INPUT}
          />
        </Field>
      </div>

      <fieldset className="space-y-2">
        <legend className="text-xs font-medium text-gray-600">Resources and their actions</legend>
        {draft.resources.map((row, rowIndex) => (
          <div key={rowIndex} className="flex flex-wrap items-center gap-2">
            <input
              value={row.name}
              onChange={(e) => updateRow(rowIndex, { name: e.target.value })}
              placeholder="resource"
              className="w-40 rounded-lg border border-gray-200 px-2.5 py-1.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
            <input
              value={row.actionsText}
              onChange={(e) => updateRow(rowIndex, { actionsText: e.target.value })}
              placeholder="view, manage"
              className="min-w-48 flex-1 rounded-lg border border-gray-200 px-2.5 py-1.5 font-mono text-xs text-gray-700 focus:border-[#001E2B] focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10"
            />
            <button
              type="button"
              onClick={() => setDraft((current) => ({ ...current, resources: current.resources.filter((_, i) => i !== rowIndex) }))}
              className="rounded-lg border border-gray-200 p-1.5 text-gray-400 hover:bg-gray-50"
            >
              <Trash2 size={12} aria-hidden />
            </button>
          </div>
        ))}
        <button
          type="button"
          onClick={() => setDraft((current) => ({ ...current, resources: [...current.resources, { name: '', actionsText: '' }] }))}
          className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-700"
        >
          <Plus size={11} aria-hidden />
          Add a resource
        </button>
        <p className="text-[11px] text-gray-400">
          Removing a resource or an action here and saving is how it is withdrawn: kept for the
          record rather than deleted, since a role may already grant it.
        </p>
      </fieldset>

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={busy || !dirty || !draft.name.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-[#001E2B] bg-[#001E2B] px-3 py-1.5 text-xs font-medium text-[#00ED64] transition-colors hover:bg-[#00303f] focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] disabled:opacity-50"
        >
          <Save size={12} aria-hidden />
          {busy ? 'Registering…' : 'Register'}
        </button>
        <ActionButton icon={X} label="Cancel" onClick={onCancel} />
      </div>
    </form>
  );
}
