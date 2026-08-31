'use client';
import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { ADMIN_TOKEN_KEY } from '../../../lib/adminHelpers';
import { Package, Terminal, ScrollText, Info, LogOut, Home, Webhook, Activity } from 'lucide-react';

const TABS = [
  { path: '/admin/panel/info',       label: 'System Info', icon: Info,       shortLabel: 'Info'    },
  { path: '/admin/panel/setup',      label: 'Setup',       icon: Package,    shortLabel: 'Setup'   },
  { path: '/admin/panel/logs',       label: 'Server Logs', icon: ScrollText, shortLabel: 'Logs'    },
  { path: '/admin/panel/terminal',   label: 'Terminal',    icon: Terminal,   shortLabel: 'Term'    },
  { path: '/admin/panel/webhook',    label: 'Webhook',     icon: Webhook,    shortLabel: 'Hook'    },
  { path: '/admin/panel/monitoring', label: 'Monitoring',  icon: Activity,   shortLabel: 'Monitor' },
];

export default function PanelLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const t = sessionStorage.getItem(ADMIN_TOKEN_KEY);
    if (!t) { router.push('/admin'); return; }
    setReady(true);
  }, [router]);

  if (!ready) return <div className="text-center py-12 text-gray-500">Redirecting...</div>;

  return (
    <div className="flex flex-col lg:h-full gap-4">
      {/* Header row */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-white">Admin Panel</h1>
          <p className="text-gray-500 text-xs sm:text-sm mt-0.5 hidden sm:block">
            Demo environment setup and monitoring
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors"
          >
            <Home size={13} />
            <span className="hidden sm:inline">Back to Home</span>
          </Link>
          <button
            onClick={() => { sessionStorage.removeItem(ADMIN_TOKEN_KEY); router.push('/admin'); }}
            className="inline-flex items-center gap-1.5 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-2.5 py-1.5 rounded-lg transition-colors"
          >
            <LogOut size={13} />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </div>

      {/* Tabs - horizontally scrollable on mobile */}
      <div className="overflow-x-auto -mx-3 sm:mx-0 px-3 sm:px-0">
        <div className="flex gap-1 border-b border-gray-800 min-w-max sm:min-w-0">
          {TABS.map(({ path, label, shortLabel, icon: Icon }) => {
            const active = pathname === path;
            return (
              <Link
                key={path}
                href={path}
                className={`inline-flex items-center gap-1.5 px-3 sm:px-4 py-2 text-xs sm:text-sm font-medium rounded-t-lg transition-colors whitespace-nowrap ${
                  active
                    ? 'bg-gray-800 text-orange-400 border-b-2 border-orange-400'
                    : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/40'
                }`}
              >
                <Icon size={14} />
                <span className="hidden sm:inline">{label}</span>
                <span className="sm:hidden">{shortLabel}</span>
              </Link>
            );
          })}
        </div>
      </div>

      {/* Page content - fills remaining height on desktop; flows naturally on mobile */}
      <div className="min-w-0 lg:flex-1 lg:min-h-0">{children}</div>
    </div>
  );
}
