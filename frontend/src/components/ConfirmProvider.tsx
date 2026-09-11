'use client';

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

/**
 * A confirmation the console's own design renders, never the browser's native one.
 *
 * `window.confirm` cannot be themed, cannot wrap a long message readably, and stops the whole page
 * dead rather than reading as part of the application. `useConfirm()` is its drop-in async
 * replacement: `if (!(await confirm('Remove this role?'))) return;` reads the same as the call it
 * replaces, wherever one was needed.
 *
 * One exception, and it is a browser limitation rather than a choice: the "leave this page?" prompt
 * a `beforeunload` handler triggers is native chrome no page can replace or theme, by design, so it
 * to stays exactly as it is anywhere it is used.
 */

export interface ConfirmOptions {
  title?: string;
  message: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** `danger` reads as a warning (removing, retiring, withdrawing something). @default 'danger' */
  tone?: 'danger' | 'primary';
}

type ConfirmFn = (options: ConfirmOptions | string) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmFn | null>(null);

export function useConfirm(): ConfirmFn {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error('useConfirm() must be called beneath <ConfirmProvider>.');
  return confirm;
}

interface PendingConfirm {
  options: ConfirmOptions;
  resolve: (confirmed: boolean) => void;
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirm = useCallback<ConfirmFn>((options) => {
    const resolved = typeof options === 'string' ? { message: options } : options;
    return new Promise<boolean>((resolve) => setPending({ options: resolved, resolve }));
  }, []);

  const settle = useCallback((confirmed: boolean) => {
    setPending((current) => {
      current?.resolve(confirmed);
      return null;
    });
  }, []);

  useEffect(() => {
    if (!pending) return;
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') settle(false); };
    window.addEventListener('keydown', onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      window.removeEventListener('keydown', onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [pending, settle]);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {pending && typeof document !== 'undefined' && createPortal(
        <div
          className="fixed inset-0 z-[300] flex items-center justify-center bg-black/50 p-4"
          onClick={() => settle(false)}
          role="presentation"
        >
          <div
            className="w-full max-w-sm rounded-xl border border-gray-200 bg-white p-5 shadow-xl"
            onClick={(event) => event.stopPropagation()}
            role="alertdialog"
            aria-modal="true"
            aria-label={typeof pending.options.title === 'string' ? pending.options.title : 'Confirm'}
          >
            {pending.options.title && (
              <h2 className="font-semibold text-[#001E2B]">{pending.options.title}</h2>
            )}
            <p className={`text-sm text-gray-600 ${pending.options.title ? 'mt-1.5' : ''}`}>{pending.options.message}</p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                autoFocus
                onClick={() => settle(false)}
                className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 transition-colors hover:bg-gray-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
              >
                {pending.options.cancelLabel ?? 'Cancel'}
              </button>
              <button
                type="button"
                onClick={() => settle(true)}
                className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${
                  (pending.options.tone ?? 'danger') === 'danger'
                    ? 'border-red-200 bg-red-600 text-white hover:bg-red-700'
                    : 'border-[#001E2B] bg-[#001E2B] text-[#00ED64] hover:bg-[#00303f]'
                }`}
              >
                {pending.options.confirmLabel ?? 'Continue'}
              </button>
            </div>
          </div>
        </div>,
        document.body,
      )}
    </ConfirmContext.Provider>
  );
}
