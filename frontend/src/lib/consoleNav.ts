'use client';

import { Activity, AppWindow, Building2, Globe, HelpCircle, KeyRound, KeySquare, LayoutGrid, MonitorSmartphone, Scale, ShieldCheck, ShieldHalf, Layers, UserRound, UsersRound, type LucideIcon } from 'lucide-react';
import { can, type Claims } from './console';

/**
 * Every section the console offers, in one list.
 *
 * The sidebar, the small-screen navigation and the dashboard cards all read this, so a section can
 * never appear in one and be missing from another. `visible` decides from the claims alone, and a
 * section the claims cannot open is not rendered: a link that answers 403 teaches the reader nothing
 * except that the console does not know what it is showing them.
 */

/**
 * Which end of the sidebar a section belongs to.
 *
 * `panel` is the authority itself: the realm's principals, roles, keys, sessions. `account` is the
 * signed-in person: who they are, what they authorised, how they authenticate, and where to read
 * about any of it. Splitting them is the point, because the two groups answer different questions and
 * a reader looking for their own credentials should not have to scan an administration list to find
 * them.
 */
export type ConsoleGroup = 'panel' | 'account';

export interface ConsoleSection {
  key: string;
  label: string;
  path: string;
  icon: LucideIcon;
  /** One line, for the sidebar tooltip and the dashboard card. */
  description: string;
  exact?: boolean;
  /** Defaults to `panel`, so a section added without thinking about it lands with the rest. */
  group?: ConsoleGroup;
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
    key: 'clients',
    label: 'Applications',
    path: '/system/clients',
    icon: AppWindow,
    description: 'Applications you registered for sign-in, their redirect addresses and their secrets.',
    // Registering an application is self-service, so this is never hidden. What the permission changes
    // is how much of the realm it lists, and the authority narrows the query either way.
    visible: () => true,
  },
  {
    key: 'realms',
    label: 'Realms',
    path: '/system/realms',
    icon: Building2,
    description: 'Every trust and key boundary this deployment hosts.',
    visible: (claims) => can(claims, 'realms', 'view'),
  },
  {
    key: 'domains',
    label: 'Domains',
    path: '/system/domains',
    icon: Globe,
    description: 'Every way a person can prove who they are in this realm, and who may sign in through it.',
    // Named `providers` in the permission model: a domain IS an authentication provider here.
    visible: (claims) => can(claims, 'providers', 'view'),
  },
  {
    key: 'identities',
    label: 'Principals',
    path: '/system/identities',
    icon: UsersRound,
    description: 'People, services and workloads this authority knows about, and their lifecycle.',
    // Listing the directory is never a self-scoped act, so this one is absent without the permission.
    visible: (claims) => can(claims, 'identities', 'view'),
  },
  {
    key: 'sessions',
    label: 'Sessions',
    path: '/system/sessions',
    icon: MonitorSmartphone,
    description: 'Where this account is signed in, and ending a session everywhere at once.',
    // Never hidden: seeing where your own account is signed in and being able to end it is account
    // security, not administration. The permission decides how much of the realm is listed, and the
    // authority narrows the answer either way.
    visible: () => true,
  },
  {
    key: 'roles',
    label: 'Roles',
    path: '/system/roles',
    icon: ShieldHalf,
    description: 'Named permission sets, what each grants once composed, and who holds them.',
    // Administering a realm. Absent rather than refused for anyone else, because a link that answers
    // 403 teaches the reader only that the console does not know what it is showing them.
    visible: (claims) => can(claims, 'roles', 'view'),
  },
  {
    key: 'policies',
    label: 'Policies',
    path: '/system/policies',
    icon: Scale,
    description: 'Conditional statements evaluated after roles, and a simulator that shows which one decides.',
    // Administrative, like roles. Absent rather than refused for anyone else, because a link that
    // answers 403 teaches the reader only that the console does not know what it is showing them.
    visible: (claims) => can(claims, 'policies', 'view'),
  },
  {
    key: 'keys',
    label: 'Signing keys',
    path: '/system/keys',
    icon: KeySquare,
    description: 'What this realm signs with, what still verifies, and which replica holds each key.',
    visible: (claims) => can(claims, 'keys', 'view'),
  },

  // ── The signed-in person, pinned to the foot of the sidebar ─────────────────────────────────────
  {
    key: 'profile',
    label: 'Profile',
    path: '/system/profile',
    icon: UserRound,
    description: 'Who the authority says you are, and what your current token allows.',
    group: 'account',
    // Everybody can read their own profile, so this one is never hidden.
    visible: () => true,
  },
  {
    key: 'applications',
    // Named for what it holds: consents this person granted, not the registry of registered clients.
    // "Applications" alone reads as the registry, which is an operator surface and a different thing.
    label: 'Authorized apps',
    path: '/system/applications',
    icon: Layers,
    description: 'Applications you allowed to act on your behalf, what each may do, and when you granted it.',
    group: 'account',
    visible: () => true,
  },
  {
    key: 'credentials',
    label: 'Authenticators',
    path: '/system/credentials',
    icon: KeyRound,
    description: 'Devices registered to approve a sign-in for you. Retire one you no longer hold.',
    group: 'account',
    visible: () => true,
  },
  {
    key: 'help',
    label: 'Help and roles',
    path: '/system/help',
    icon: HelpCircle,
    description: 'What this authority is for, what each role may do, and the standards it speaks.',
    group: 'account',
    visible: () => true,
  },
];

export function visibleSections(claims: Claims | null): ConsoleSection[] {
  return CONSOLE_SECTIONS.filter((section) => section.visible(claims));
}

export function inGroup(sections: ConsoleSection[], group: ConsoleGroup): ConsoleSection[] {
  return sections.filter((section) => (section.group ?? 'panel') === group);
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
