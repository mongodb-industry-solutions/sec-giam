'use client';
import { type CSSProperties, useEffect, useMemo, useState } from 'react';
import ReactJsonView from '@uiw/react-json-view';
import { lightTheme } from '@uiw/react-json-view/light';
import { darkTheme } from '@uiw/react-json-view/dark';
import { createPortal } from 'react-dom';
import { ChevronsDownUp, ChevronsUpDown, Copy, Check, Maximize2, X } from 'lucide-react';

// Reusable read-only JSON viewer: syntax-highlighted collapsible tree with
// expand/collapse-all and copy. Themed for the app's light (admin forms) and
// dark (#001E2B raw/debug panels) surfaces. Falls back to a <pre> for primitives
// and for the pre-hydration render (avoids SSR/window issues).

export interface JsonViewProps {
  /** Object/array to render. Strings are parsed as JSON when possible. */
  data: unknown;
  theme?: 'light' | 'dark';
  /** CSS max-height for the scroll area, e.g. '20rem' or 320. @default '20rem' */
  maxHeight?: string | number;
  /** Initial collapse depth (number) or fully collapsed (true). @default 2 */
  collapsed?: number | boolean;
  /** Hide the toolbar (expand/collapse all + copy). @default false */
  hideToolbar?: boolean;
  /**
   * Override the container background/border classes to match the surrounding
   * section (e.g. "bg-gray-900 border-gray-800"). The JSON tree itself is always
   * transparent and inherits this background. Defaults to the theme's surface.
   */
  surfaceClassName?: string;
  className?: string;
  /** Show the "expand to fullscreen" toolbar action. @default true */
  allowFullscreen?: boolean;
  /** Label shown in the fullscreen overlay header. @default 'JSON' */
  fullscreenTitle?: string;
}

/** Coerce input into something the tree can render; null when it's not an object. */
function toRenderable(data: unknown): object | null {
  if (data && typeof data === 'object') return data as object;
  if (typeof data === 'string') {
    try {
      const parsed = JSON.parse(data);
      if (parsed && typeof parsed === 'object') return parsed as object;
    } catch { /* not JSON; render as text below */ }
  }
  return null;
}

function asText(data: unknown): string {
  if (data === null || data === undefined) return String(data);
  if (typeof data === 'string') return data;
  try { return JSON.stringify(data, null, 2); } catch { return String(data); }
}

export function JsonView({
  data,
  theme = 'light',
  maxHeight = '20rem',
  collapsed = 2,
  hideToolbar = false,
  surfaceClassName,
  className = '',
  allowFullscreen = true,
  fullscreenTitle = 'JSON',
}: JsonViewProps) {
  const [mounted, setMounted] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  // Measured visual viewport, used to size the fullscreen overlay on mobile.
  const [viewport, setViewport] = useState({ width: 0, height: 0, top: 0, left: 0 });
  const [copied, setCopied] = useState(false);
  // Bumped to remount the tree when toggling expand/collapse-all.
  const [renderKey, setRenderKey] = useState(0);
  const [collapseState, setCollapseState] = useState<number | boolean>(collapsed);

  useEffect(() => { setMounted(true); }, []);

  // Fullscreen overlay: close on Escape, lock the page behind it, and track the
  // visual viewport. Mobile browsers report a stale height for 100dvh/inset-0
  // while the URL bar collapses or the keyboard is open, which leaves the dialog
  // short of the real screen; measuring visualViewport is the only reliable size.
  useEffect(() => {
    if (!fullscreen) return;

    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setFullscreen(false); };
    const vv = window.visualViewport;
    const measure = () => setViewport({
      width: vv?.width ?? window.innerWidth,
      height: vv?.height ?? window.innerHeight,
      top: vv?.offsetTop ?? 0,
      left: vv?.offsetLeft ?? 0,
    });

    measure();
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', onKey);
    window.addEventListener('resize', measure);
    window.addEventListener('orientationchange', measure);
    vv?.addEventListener('resize', measure);
    vv?.addEventListener('scroll', measure);

    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', measure);
      window.removeEventListener('orientationchange', measure);
      vv?.removeEventListener('resize', measure);
      vv?.removeEventListener('scroll', measure);
    };
  }, [fullscreen]);

  const renderable = useMemo(() => toRenderable(data), [data]);
  const isDark = theme === 'dark';
  const maxH = typeof maxHeight === 'number' ? `${maxHeight}px` : maxHeight;

  const copyAll = () => {
    navigator.clipboard.writeText(asText(data)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  const toggle = (next: number | boolean) => {
    setCollapseState(next);
    setRenderKey((k) => k + 1);
  };

  const surface = surfaceClassName ?? (isDark
    ? 'bg-[#001E2B] border-[#0a3a4a]'
    : 'bg-gray-50 border-gray-200');
  // Neutral translucent divider works on any surface (teal, gray-900, light).
  const divider = isDark ? 'border-white/10' : 'border-black/10';
  const btn = isDark
    ? 'text-gray-400 hover:text-gray-100'
    : 'text-gray-500 hover:text-gray-800';
  // Toolbar buttons keep a touch-friendly hit area; labels collapse to icons on phones.
  const action = `inline-flex items-center gap-1 text-[11px] min-h-[28px] px-0.5 shrink-0 ${btn} transition-colors`;
  // The tree inherits the container background instead of painting its own,
  // so it blends with whatever surface the caller provides.
  const treeStyle = {
    ...(isDark ? darkTheme : lightTheme),
    '--w-rjv-background-color': 'transparent',
    fontSize: 'inherit',
  } as CSSProperties;

  // Toolbar + scroll area, reused by the inline viewer and the fullscreen overlay.
  const viewer = (isOverlay: boolean) => (
    <>
      {!hideToolbar && (
        <div className={`flex items-center gap-x-3 gap-y-1 flex-wrap px-2 @[20rem]:px-3 py-1.5 border-b ${divider}`}>
          {renderable && (
            <>
              <button type="button" onClick={() => toggle(false)} className={action} title="Expand all">
                <ChevronsUpDown size={12} /> <span className="hidden @[22rem]:inline">Expand all</span>
              </button>
              <button type="button" onClick={() => toggle(true)} className={action} title="Collapse all">
                <ChevronsDownUp size={12} /> <span className="hidden @[22rem]:inline">Collapse all</span>
              </button>
            </>
          )}
          <button type="button" onClick={copyAll} className={`${action} ml-auto`} title="Copy JSON">
            {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
            <span className="hidden @[16rem]:inline">{copied ? 'Copied' : 'Copy'}</span>
          </button>
          {allowFullscreen && !isOverlay && (
            <button type="button" onClick={() => setFullscreen(true)} className={action} title="Expand to fullscreen">
              <Maximize2 size={12} /> <span className="hidden @[30rem]:inline">Fullscreen</span>
            </button>
          )}
        </div>
      )}
      <div
        className={`overflow-auto px-2 @[20rem]:px-3 py-2.5 text-[11px] @[30rem]:text-[13px] [overflow-wrap:anywhere] ${isOverlay ? 'flex-1 min-h-0' : ''}`}
        style={isOverlay ? undefined : { maxHeight: maxH }}
      >
        {renderable ? (
          <ReactJsonView
            key={`${renderKey}-${isOverlay ? 'fs' : 'in'}`}
            value={renderable}
            collapsed={collapseState}
            style={treeStyle}
            displayDataTypes={false}
            displayObjectSize
            enableClipboard
            shortenTextAfterLength={0}
          />
        ) : (
          <pre className={`font-mono whitespace-pre-wrap break-all ${isDark ? 'text-green-300' : 'text-gray-700'}`}>
            {asText(data) || <span className="italic opacity-60">empty</span>}
          </pre>
        )}
      </div>
    </>
  );

  // Pre-hydration: plain <pre>, no portal and no toolbar (avoids SSR mismatch).
  if (!mounted) {
    return (
      <div className={`rounded-lg border overflow-hidden ${surface} ${className}`}>
        <pre
          className={`text-xs font-mono px-3 py-2.5 overflow-auto whitespace-pre-wrap break-all ${isDark ? 'text-green-300' : 'text-gray-700'}`}
          style={{ maxHeight: maxH }}
        >
          {asText(data) || <span className="italic opacity-60">empty</span>}
        </pre>
      </div>
    );
  }

  return (
    <>
      <div className={`@container rounded-lg border overflow-hidden ${surface} ${className}`}>
        {viewer(false)}
      </div>

      {fullscreen && createPortal(
        <div
          className="fixed inset-0 z-[100] bg-black/70 backdrop-blur-sm flex p-0 sm:p-4 md:p-6 overscroll-contain"
          style={viewport.height > 0 ? {
            top: viewport.top,
            left: viewport.left,
            width: viewport.width,
            height: viewport.height,
            right: 'auto',
            bottom: 'auto',
          } : undefined}
          onClick={() => setFullscreen(false)}
          role="dialog"
          aria-modal="true"
          aria-label={fullscreenTitle}
        >
          <div
            className={`@container mx-auto w-full h-full min-h-0 max-w-[1600px] flex flex-col overflow-hidden border-0 rounded-none sm:border sm:rounded-lg ${surface}`}
            onClick={e => e.stopPropagation()}
          >
            <div className={`flex items-center gap-2 px-2 @[20rem]:px-3 py-2 border-b ${divider}`}>
              <span className={`text-[11px] @[30rem]:text-xs font-semibold truncate ${isDark ? 'text-[#00ED64]' : 'text-gray-700'}`}>
                {fullscreenTitle}
              </span>
              <button type="button" onClick={() => setFullscreen(false)} className={`${action} ml-auto`} title="Close (Esc)">
                <X size={14} /> <span className="hidden @[16rem]:inline">Close</span>
              </button>
            </div>
            <div className="flex-1 min-h-0 flex flex-col">
              {viewer(true)}
            </div>
          </div>
        </div>,
        document.body
      )}
    </>
  );
}

export default JsonView;
