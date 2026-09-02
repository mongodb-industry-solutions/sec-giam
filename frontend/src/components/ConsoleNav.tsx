'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ChevronLeft, ChevronRight } from 'lucide-react';
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

/** Small screens: the same sections as a fixed bar, so nothing is reachable only on a desktop. */
export function ConsoleMobileNav({ claims }: { claims: Claims | null }) {
  const { sections, isActive } = useSections(claims);

  return (
    <nav
      aria-label="Console sections"
      className="fixed inset-x-0 bottom-0 z-30 flex border-t border-white/10 bg-[#001E2B] md:hidden print:hidden"
    >
      {sections.map((section) => {
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
    </nav>
  );
}
