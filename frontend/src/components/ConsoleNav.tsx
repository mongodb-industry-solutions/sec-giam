'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronLeft, ChevronRight, Menu, X } from 'lucide-react';
import { activeSection, inGroup, visibleSections, type ConsoleSection } from '../lib/consoleNav';
import type { Claims } from '../lib/console';

const COLLAPSED_KEY = 'giam.sidebar.collapsed';

function useSections(claims: Claims | null) {
  const pathname = usePathname();
  const sections = visibleSections(claims);
  const active = activeSection(sections, pathname);
  return { sections, isActive: (section: ConsoleSection) => active?.key === section.key };
}

/** Desktop and tablet navigation. Collapsed to icons by default, and the choice is remembered. */
export function ConsoleSidebar({ claims }: { claims: Claims | null }) {
  const { sections, isActive } = useSections(claims);
  const [collapsed, setCollapsed] = useState(true);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(COLLAPSED_KEY);
      if (saved !== null) setCollapsed(saved === 'true');
    } catch {}
  }, []);

  const toggle = useCallback(() => {
    setCollapsed((value) => {
      const next = !value;
      try { localStorage.setItem(COLLAPSED_KEY, String(next)); } catch {}
      return next;
    });
  }, []);

  return (
    <aside
      className={`sticky top-12 hidden h-[calc(100vh-3rem)] shrink-0 flex-col border-r border-white/10 bg-[#001E2B] transition-all duration-200 md:flex print:hidden ${
        collapsed ? 'w-14' : 'w-52'
      }`}
    >
      {/* `flex-1` on the scrolling nav is what pushes the account block to the foot: it takes the free
          space, so its sibling below has nowhere to go but the bottom edge. */}
      <nav aria-label="Console sections" className="min-h-0 flex-1 overflow-y-auto py-3">
        <div className="flex items-center justify-between px-3 pb-2">
          {!collapsed && <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">Console</p>}
          <button
            type="button"
            onClick={toggle}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            className={`flex items-center justify-center rounded p-0.5 text-gray-400 transition-colors hover:bg-white/10 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64] ${collapsed ? 'mx-auto' : 'ml-auto'}`}
          >
            {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </button>
        </div>

        {inGroup(sections, 'panel').map((section) => (
          <SidebarLink key={section.key} section={section} active={isActive(section)} collapsed={collapsed} />
        ))}
      </nav>

      <div aria-label="Your account" className="border-t border-white/10 py-1">
        {inGroup(sections, 'account').map((section) => (
          <SidebarLink key={section.key} section={section} active={isActive(section)} collapsed={collapsed} />
        ))}
      </div>
    </aside>
  );
}

function SidebarLink({ section, active, collapsed }: {
  section: ConsoleSection;
  active: boolean;
  collapsed: boolean;
}) {
  const Icon = section.icon;
  return (
    <Link
      href={section.path}
      title={collapsed ? `${section.label}: ${section.description}` : section.description}
      aria-current={active ? 'page' : undefined}
      className={`relative flex items-center gap-2.5 px-4 py-2.5 text-sm font-medium transition-colors focus:outline-none focus-visible:bg-white/10 ${
        active
          ? 'border-r-2 border-[#00ED64] bg-[#00ED64]/10 text-[#00ED64]'
          : 'text-gray-400 hover:bg-white/5 hover:text-white'
      }`}
    >
      <Icon size={16} className="shrink-0" />
      {!collapsed && <span className="truncate">{section.label}</span>}
    </Link>
  );
}

// A bottom bar squeezes every item to a sliver once the console grows past a handful of sections,
// which is exactly what happened: 14 sections in a `flex-1` row means each one is unreadable and
// several are unreachable, with no affordance saying there is anything to scroll to. Only a few
// stay pinned to the bar; the rest live in a sheet that scrolls, which is a control the person can
// actually see and use, not a strip that quietly runs out of room.
const PINNED_MOBILE_SECTIONS = 3;

/** Small screens: a few pinned sections plus a scrollable sheet with everything else. */
export function ConsoleMobileNav({ claims }: { claims: Claims | null }) {
  const { sections, isActive } = useSections(claims);
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  // Closed on every navigation, so choosing a section from the sheet does not leave it open behind
  // the new page.
  useEffect(() => { setOpen(false); }, [pathname]);

  const pinned = sections.slice(0, PINNED_MOBILE_SECTIONS);
  const activeIsPinned = pinned.some((section) => isActive(section));

  return (
    <>
      <nav
        aria-label="Console sections"
        className="fixed inset-x-0 bottom-0 z-30 flex border-t border-white/10 bg-[#001E2B] md:hidden print:hidden"
      >
        {pinned.map((section) => {
          const Icon = section.icon;
          const active = isActive(section);
          return (
            <Link
              key={section.key}
              href={section.path}
              aria-current={active ? 'page' : undefined}
              aria-label={section.label}
              className={`flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px] font-medium transition-colors focus:outline-none focus-visible:bg-white/10 ${
                active ? 'text-[#00ED64]' : 'text-gray-400'
              }`}
            >
              <Icon size={17} />
              <span className="max-w-full truncate px-0.5">{section.label}</span>
            </Link>
          );
        })}
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label="More sections"
          aria-expanded={open}
          className={`flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px] font-medium transition-colors focus:outline-none focus-visible:bg-white/10 ${
            !activeIsPinned ? 'text-[#00ED64]' : 'text-gray-400'
          }`}
        >
          <Menu size={17} />
          <span className="max-w-full truncate px-0.5">More</span>
        </button>
      </nav>

      {open && (
        <MobileSectionSheet sections={sections} isActive={isActive} onClose={() => setOpen(false)} />
      )}
    </>
  );
}

/** Every section, grouped exactly like the desktop sidebar, in a list that scrolls on its own. */
function MobileSectionSheet({ sections, isActive, onClose }: {
  sections: ConsoleSection[];
  isActive: (section: ConsoleSection) => boolean;
  onClose: () => void;
}) {
  useEffect(() => {
    // The sheet covers the page; the page itself must not also scroll behind it.
    const previous = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = previous; };
  }, []);

  return (
    <div className="fixed inset-0 z-40 flex flex-col bg-[#001E2B] md:hidden print:hidden" role="dialog" aria-modal="true" aria-label="All console sections">
      <div className="flex shrink-0 items-center justify-between border-b border-white/10 px-4 py-3">
        <p className="text-sm font-semibold uppercase tracking-wider text-gray-400">Console sections</p>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="flex h-8 w-8 items-center justify-center rounded-lg text-gray-300 hover:bg-white/10 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
        >
          <X size={18} />
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto pb-[env(safe-area-inset-bottom)]">
        <SheetGroup label={undefined} sections={inGroup(sections, 'panel')} isActive={isActive} onClose={onClose} />
        <SheetGroup label="Your account" sections={inGroup(sections, 'account')} isActive={isActive} onClose={onClose} />
      </div>
    </div>
  );
}

function SheetGroup({ label, sections, isActive, onClose }: {
  label?: string;
  sections: ConsoleSection[];
  isActive: (section: ConsoleSection) => boolean;
  onClose: () => void;
}) {
  if (sections.length === 0) return null;
  return (
    <div className="border-b border-white/5 py-2">
      {label && <p className="px-4 pb-1 pt-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500">{label}</p>}
      {sections.map((section) => {
        const Icon = section.icon;
        const active = isActive(section);
        return (
          <Link
            key={section.key}
            href={section.path}
            onClick={onClose}
            aria-current={active ? 'page' : undefined}
            className={`flex items-center gap-3 px-4 py-3 text-sm font-medium transition-colors focus:outline-none focus-visible:bg-white/10 ${
              active ? 'bg-[#00ED64]/10 text-[#00ED64]' : 'text-gray-300 hover:bg-white/5 hover:text-white'
            }`}
          >
            <Icon size={18} className="shrink-0" />
            <span className="min-w-0 flex-1 truncate">{section.label}</span>
          </Link>
        );
      })}
    </div>
  );
}
