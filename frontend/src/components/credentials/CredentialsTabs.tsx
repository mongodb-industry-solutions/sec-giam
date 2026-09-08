'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

/**
 * The credential section's own tabs.
 *
 * One collection underneath (ADR-001: an OAuth application is a `credential` of type `oauth_client`,
 * the same record kind as a password or an authenticator), split here by type because registering an
 * application and enrolling a passkey are different forms for a different moment, not because they
 * are different kinds of thing to the authority.
 */

const TABS = [
  { href: '/system/credentials/applications', label: 'Applications' },
  { href: '/system/credentials/authenticators', label: 'Authenticators' },
];

export function CredentialsTabs() {
  const pathname = usePathname();

  return (
    <nav aria-label="Credential sections" className="flex flex-wrap gap-1 border-b border-gray-200 pb-2">
      {TABS.map((tab) => {
        const active = pathname.startsWith(tab.href);
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
