'use client';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

interface Props {
  /** Plain text, or rich content when an inline icon makes the hint clearer than describing it. */
  text: ReactNode;
  /** Wrap an existing control instead of rendering the ⓘ glyph. Use it to replace a native `title`. */
  children?: ReactNode;
}

interface Position {
  top: number;
  left: number;
  below: boolean;
  /** Bubble width in px, shrunk on narrow screens so it always fits. */
  width: number;
  /** Arrow offset from the bubble's left edge, so it keeps pointing at the trigger when clamped. */
  arrow: number;
}

// Enough room for the tallest bubble the fixed width produces.
const ESTIMATED_HEIGHT = 96;
const MAX_WIDTH = 256;   // w-64
const EDGE_GAP = 8;      // breathing room against the viewport edges

export function Tooltip({ text, children }: Props) {
  const [visible, setVisible] = useState(false);
  const [pos, setPos] = useState<Position>({ top: 0, left: 0, below: false, width: MAX_WIDTH, arrow: MAX_WIDTH / 2 });
  const [mounted, setMounted] = useState(false);
  const triggerRef = useRef<HTMLSpanElement>(null);

  useEffect(() => { setMounted(true); }, []);

  function show() {
    // The wrapper uses display:contents so it never disturbs layout, and therefore has no box of its
    // own: measure the trigger element instead.
    const el = (triggerRef.current?.firstElementChild as HTMLElement | null) ?? triggerRef.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const below = r.top < ESTIMATED_HEIGHT;
    // Narrow screens: shrink the bubble and clamp it inside the viewport, otherwise a trigger near
    // an edge pushed half the text off screen. The arrow then absorbs the shift.
    const vw = window.innerWidth;
    const width = Math.min(MAX_WIDTH, vw - EDGE_GAP * 2);
    const center = r.left + r.width / 2;
    const half = width / 2;
    const left = Math.min(Math.max(center, EDGE_GAP + half), vw - EDGE_GAP - half);
    setPos({ top: below ? r.bottom : r.top, left, below, width, arrow: center - (left - half) });
    setVisible(true);
  }
  const hide = () => setVisible(false);

  return (
    <span className={children ? 'contents' : 'inline-block ml-1 align-middle'}>
      {/* A wrapped control is often a <button>, so the trigger must not be one itself. */}
      <span
        ref={triggerRef}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        // Touch devices have no hover: a tap on the ⓘ toggles the bubble. Wrapped controls keep their
        // own click behaviour untouched.
        onClick={children ? undefined : () => (visible ? hide() : show())}
        className={children ? 'contents' : 'inline-block'}
      >
        {children ?? (
          <button
            type="button"
            className="text-gray-400 hover:text-blue-500 focus:text-blue-500 focus:outline-none text-xs leading-none transition-colors"
            aria-label="More information"
          >
            ⓘ
          </button>
        )}
      </span>

      {mounted && visible && createPortal(
        <span
          style={{
            position: 'fixed',
            top: pos.below ? pos.top + 10 : pos.top - 10,
            left: pos.left,
            width: pos.width,
            transform: pos.below ? 'translate(-50%, 0)' : 'translate(-50%, -100%)',
            zIndex: 9999,
          }}
          className="rounded-lg bg-[#001E2B] text-white text-xs px-3 py-2 shadow-xl pointer-events-none leading-relaxed"
        >
          {text}
          <span
            style={{ left: Math.min(Math.max(pos.arrow, 10), pos.width - 10) }}
            className={`absolute -translate-x-1/2 border-4 border-transparent ${
              pos.below ? 'bottom-full border-b-[#001E2B]' : 'top-full border-t-[#001E2B]'}`}
          />
        </span>,
        document.body,
      )}
    </span>
  );
}
