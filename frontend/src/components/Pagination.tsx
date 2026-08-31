'use client';
import { useState } from 'react';
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from 'lucide-react';

interface Props {
  page: number;
  totalPages: number;
  total: number;
  limit: number;
  onPageChange: (page: number) => void;
  onLimitChange?: (limit: number) => void;
  limitOptions?: number[];
  noun?: string;
  variant?: 'light' | 'dark';
}

export function Pagination({
  page,
  totalPages,
  total,
  limit,
  onPageChange,
  onLimitChange,
  limitOptions = [10, 20, 50],
  noun = 'cases',
  variant = 'light',
}: Props) {
  const from = total === 0 ? 0 : (page - 1) * limit + 1;
  const to   = Math.min(page * limit, total);
  const [jumpValue, setJumpValue] = useState('');
  const dk = variant === 'dark';

  function pageNumbers(): (number | 'ellipsis')[] {
    if (totalPages <= 7) return Array.from({ length: totalPages }, (_, i) => i + 1);
    const pages: (number | 'ellipsis')[] = [1];
    const left  = Math.max(2, page - 1);
    const right = Math.min(totalPages - 1, page + 1);
    if (left > 2)               pages.push('ellipsis');
    for (let i = left; i <= right; i++) pages.push(i);
    if (right < totalPages - 1) pages.push('ellipsis');
    pages.push(totalPages);
    return pages;
  }

  function commitJump() {
    const v = parseInt(jumpValue, 10);
    if (v >= 1 && v <= totalPages) onPageChange(v);
    setJumpValue('');
  }

  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 py-2 select-none">

      {/* Left - count */}
      <p className={`text-xs shrink-0 order-last sm:order-first ${dk ? 'text-gray-500' : 'text-gray-400'}`}>
        {total === 0
          ? <span>No {noun}</span>
          : <>
              <span className={`font-semibold ${dk ? 'text-gray-300' : 'text-gray-700'}`}>{from}</span>
              <span className="mx-0.5">–</span>
              <span className={`font-semibold ${dk ? 'text-gray-300' : 'text-gray-700'}`}>{to}</span>
              <span className={`mx-1.5 ${dk ? 'text-gray-700' : 'text-gray-200'}`}>|</span>
              <span className={`font-semibold ${dk ? 'text-gray-300' : 'text-gray-700'}`}>{total}</span>
              <span className="ml-1">{noun}</span>
            </>
        }
      </p>

      {/* Center - navigation */}
      {totalPages > 1 && (
        <nav className="flex items-center gap-0.5 order-first sm:order-none" aria-label="Pagination">
          <button type="button" onClick={() => onPageChange(1)} disabled={page === 1} aria-label="First page" className={navBtn(page === 1, dk)}>
            <ChevronsLeft size={13} />
          </button>
          <button type="button" onClick={() => onPageChange(page - 1)} disabled={page === 1} aria-label="Previous page" className={navBtn(page === 1, dk)}>
            <ChevronLeft size={13} />
          </button>

          <div className="flex items-center gap-0.5 mx-1">
            {pageNumbers().map((p, i) =>
              p === 'ellipsis' ? (
                <span key={`e${i}`} className={`w-8 h-8 flex items-center justify-center text-sm tracking-widest ${dk ? 'text-gray-600' : 'text-gray-300'}`}>
                  ···
                </span>
              ) : (
                <button type="button" key={p} onClick={() => onPageChange(p)} aria-current={p === page ? 'page' : undefined} className={pageBtn(p === page, dk)}>
                  {p}
                </button>
              )
            )}
          </div>

          <button type="button" onClick={() => onPageChange(page + 1)} disabled={page === totalPages} aria-label="Next page" className={navBtn(page === totalPages, dk)}>
            <ChevronRight size={13} />
          </button>
          <button type="button" onClick={() => onPageChange(totalPages)} disabled={page === totalPages} aria-label="Last page" className={navBtn(page === totalPages, dk)}>
            <ChevronsRight size={13} />
          </button>

          {/* Jump-to-page */}
          <div className={`flex items-center gap-1.5 ml-2 pl-3 border-l ${dk ? 'border-gray-700' : 'border-gray-100'}`}>
            <span className={`text-xs hidden sm:block ${dk ? 'text-gray-500' : 'text-gray-300'}`}>Go to</span>
            <input
              type="number"
              min={1}
              max={totalPages}
              value={jumpValue}
              onChange={(e) => setJumpValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && commitJump()}
              onBlur={commitJump}
              placeholder={String(page)}
              className={`w-10 h-8 rounded-lg border text-xs text-center transition-colors focus:outline-none focus:ring-2 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none ${
                dk
                  ? 'bg-gray-800 border-gray-700 text-gray-300 placeholder-gray-600 hover:border-gray-600 focus:border-orange-500 focus:ring-orange-500/20'
                  : 'bg-white border-gray-200 text-gray-700 placeholder-gray-300 hover:border-gray-300 focus:border-[#001E2B] focus:ring-[#001E2B]/10'
              }`}
            />
          </div>
        </nav>
      )}

      {/* Right - per-page toggle */}
      {onLimitChange && (
        <div className="flex items-center gap-2 shrink-0 order-first sm:order-last">
          <span className={`text-xs ${dk ? 'text-gray-500' : 'text-gray-400'}`}>Per page</span>
          <div className={`flex items-center gap-0.5 rounded-lg p-0.5 ${dk ? 'bg-gray-800 border border-gray-700' : 'bg-gray-100'}`}>
            {limitOptions.map((opt) => (
              <button
                key={opt}
                type="button"
                onClick={() => onLimitChange(opt)}
                className={`h-6 min-w-[30px] px-2 text-xs font-medium rounded-md transition-all duration-150 ${
                  opt === limit
                    ? dk
                      ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
                      : 'bg-[#001E2B] text-[#00ED64] shadow-sm'
                    : dk
                      ? 'text-gray-500 hover:text-gray-200 hover:bg-gray-700'
                      : 'text-gray-500 hover:text-gray-800 hover:bg-white/60'
                }`}
              >
                {opt}
              </button>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}

function navBtn(disabled: boolean, dk: boolean) {
  return `w-8 h-8 flex items-center justify-center rounded-lg transition-all duration-150 ${
    disabled
      ? dk ? 'text-gray-700 cursor-not-allowed' : 'text-gray-200 cursor-not-allowed'
      : dk
        ? 'text-gray-500 hover:bg-gray-700 hover:text-orange-400'
        : 'text-gray-400 hover:bg-[#001E2B] hover:text-[#00ED64] hover:shadow-sm'
  }`;
}

function pageBtn(active: boolean, dk: boolean) {
  return `min-w-[32px] h-8 px-1.5 flex items-center justify-center rounded-lg text-sm font-medium transition-all duration-150 ${
    active
      ? dk
        ? 'bg-orange-500/20 text-orange-400 border border-orange-500/40'
        : 'bg-[#001E2B] text-[#00ED64] shadow-sm'
      : dk
        ? 'text-gray-500 hover:bg-gray-700 hover:text-gray-200'
        : 'text-gray-500 hover:bg-[#001E2B]/6 hover:text-[#001E2B]'
  }`;
}
