'use client';

import { Activity, KeyRound, LayoutGrid, ShieldCheck, Layers, SlidersHorizontal, type LucideIcon } from 'lucide-react';
import { administersIdentity, can, type Claims } from './console';

/**
 * Every section the console offers, in one list.
 *
 * The sidebar, the small-screen navigation and the dashboard cards all read this, so a section can
 * never appear in one and be missing from another. `visible` decides from the claims alone, and a
 * section the claims cannot open is not rendered: a link that answers 403 teaches the reader nothing
 * except that the console does not know what it is showing them.
 */

export interface ConsoleSection {
  key: string;
  label: string;
  path: string;
  icon: LucideIcon;
  /** One line, for the sidebar tooltip and the dashboard card. */
  description: string;
  exact?: boolean;
  /** Leaves the console for the operations surface, which holds its own credential. */
  external?: boolean;
  visible: (claims: Claims | null) => boolean;
}

export const CONSOLE_SECTIONS: ConsoleSection[] = [
  {
    key: 'overview',
    label: 'Overview',
    path: '/system',
    icon: LayoutGrid,
    description: 'Everything this account can reach, at a glance.',
    exact: true,
    visible: () => true,
  },
  {
    key: 'applications',
    label: 'Applications',
    path: '/system/applications',
    icon: Layers,
    description: 'Applications you authorized to act for you, with what each was allowed and when.',
    visible: () => true,
  },
  {
    key: 'credentials',
    label: 'Authenticators',
    path: '/system/credentials',
    icon: KeyRound,
    description: 'Devices registered to approve a sign-in for you. Retire one you no longer hold.',
    visible: () => true,
  },
  {
    key: 'elevations',
    label: 'Privileged access',
    path: '/system/elevations',
    icon: ShieldCheck,
    description: 'Who holds temporary authority right now, and which requests are waiting.',
    visible: (claims) => can(claims, 'elevations', 'view'),
  },
  {
    key: 'activity',
    label: 'Activity',
    path: '/system/activity',
    icon: Activity,
    description: 'The identity trail: who did what, when, and whether it succeeded.',
    visible: () => true,
  },
  {
    key: 'operations',
    label: 'Operations',
    path: '/admin',
    icon: SlidersHorizontal,
    description: 'Service posture, logs and configuration. Signs in with its own operator credential.',
    external: true,
    visible: administersIdentity,
  },
];

export function visibleSections(claims: Claims | null): ConsoleSection[] {
  return CONSOLE_SECTIONS.filter((section) => section.visible(claims));
}

/** Only one section is active: the most specific path that matches, so siblings stay independent. */
export function activeSection(sections: ConsoleSection[], pathname: string): ConsoleSection | null {
  let best: ConsoleSection | null = null;
  for (const section of sections) {
    const matches = section.exact
      ? pathname === section.path
      : pathname === section.path || pathname.startsWith(`${section.path}/`);
    if (matches && (!best || section.path.length > best.path.length)) best = section;
  }
  return best;
}
