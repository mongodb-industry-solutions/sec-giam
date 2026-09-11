'use client';
import { type CSSProperties } from 'react';
import JsonViewEditor from '@uiw/react-json-view/editor';
import { lightTheme } from '@uiw/react-json-view/light';

/**
 * A JSON document, edited as a tree.
 *
 * The same `@uiw/react-json-view` this console already reads JSON with, in its editable form, so a
 * document is changed where it is displayed rather than retyped in a textarea. Editing a value in
 * the tree is what it is good at; adding a key or an array entry is not, so every caller keeps a
 * raw view beside this one and this component does not pretend to replace it.
 *
 * The value handed back is the whole document, re-serialised, because that is what a caller saves
 * and what it compares against to know whether anything changed.
 */
export function JsonDocumentEditor({ value, onChange, editable = true, maxHeight = '26rem' }: {
  /** The parsed document. A caller holding text should parse it first and keep the text as truth. */
  value: object;
  onChange: (next: string) => void;
  editable?: boolean;
  maxHeight?: string;
}) {
  const theme = {
    ...lightTheme,
    '--w-rjv-background-color': 'transparent',
    fontSize: 'inherit',
  } as CSSProperties;

  return (
    <div className="overflow-auto rounded-lg border border-gray-200 bg-gray-50 px-3 py-2.5 text-xs" style={{ maxHeight }}>
      <JsonViewEditor
        value={value}
        editable={editable}
        style={theme}
        displayDataTypes={false}
        displayObjectSize
        enableClipboard
        /**
         * The edit is applied to a COPY and the whole document is handed back.
         *
         * Returning true tells the tree the change is accepted; the tree then holds its own copy,
         * so whoever owns the document has to be told, or the two drift and a save writes the old
         * one. Mutating the object handed in would be the same bug with extra steps.
         */
        onEdit={({ value: edited, keyName, parentName }) => {
          if (keyName === undefined) return false;
          const next = structuredClone(value) as Record<string, unknown>;
          const parent = parentName === undefined
            ? next
            : (next[parentName as string] as Record<string, unknown> | undefined);
          if (!parent || typeof parent !== 'object') return false;
          (parent as Record<string, unknown>)[keyName as string] = edited;
          onChange(JSON.stringify(next, null, 2));
          return true;
        }}
      />
    </div>
  );
}

export default JsonDocumentEditor;
