'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

/** The help section's own tabs. A help page that does not say where you are is a page you leave. */

const TABS = [
  { href: '/system/help', label: 'What this is', exact: true },
  { href: '/system/help/roles', label: 'Roles' },
  { href: '/system/help/mongodb', label: 'Why MongoDB' },
  { href: '/system/help/standards', label: 'Standards' },
];

export function HelpTabs() {
  const pathname = usePathname();

  return (
    <nav aria-label="Help sections" className="flex flex-wrap gap-1 border-b border-gray-200 pb-2">
      {TABS.map((tab) => {
        const active = tab.exact ? pathname === tab.href : pathname.startsWith(tab.href);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            aria-current={active ? 'page' : undefined}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
              active ? 'bg-[#001E2B] text-[#00ED64]' : 'text-gray-500 hover:bg-gray-100 hover:text-gray-900'
            }`}
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
