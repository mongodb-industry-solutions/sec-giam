'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { BadgeCheck, ChevronRight, KeyRound, Layers, ShieldCheck, UserRound } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { Tooltip } from '../../../components/Tooltip';
import { LoadingState } from '../../../components/ResultState';
import { JsonView } from '../../../components/json/JsonView';
import {
  currentClaims,
  displayName,
  initials,
  isExpired,
  when,
  type Claims,
  type UserInfo,
} from '../../../lib/console';
import { useUserInfo } from '../../../lib/profile';
import { storedRealm } from '../../../lib/session';

/**
 * Everything the authority will say about the person holding this session.
 *
 * Two sources, kept apart on purpose. The profile comes from the UserInfo endpoint, which answers
 * who somebody is and only within the scopes they granted. The token answers what the holder may do.
 * Showing them separately is the point: a name that came from an access token would be a name no
 * verifier ever checked.
 */

function stamp(seconds?: number): string {
  return typeof seconds === 'number' ? when(new Date(seconds * 1000).toISOString()) : '';
}

export default function ProfilePage() {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [realm, setRealm] = useState('');
  const { info, loading } = useUserInfo();

  useEffect(() => {
    const found = currentClaims();
    setClaims(found && !isExpired(found) ? found : null);
    setRealm(storedRealm());
  }, []);

  if (!claims) return <main className="space-y-5"><LoadingState label="Reading your session…" /></main>;

  const who = displayName(claims);
  const username = typeof info?.preferred_username === 'string' ? info.preferred_username : claims.preferred_username;
  const email = typeof info?.email === 'string' ? info.email : claims.email;
  const verified = info?.email_verified === true;
  const roles = claims.roles ?? [];
  const scopes = (claims.scope ?? '').split(' ').filter(Boolean);
  const entitlements = claims.entitlements ?? [];
  const audience = Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud;

  return (
    <main className="space-y-5">
      <SectionHeader
        icon={UserRound}
        title="Your profile"
        description="Who the authority says you are, and what this session is allowed to do."
        info="Your name and address are read from the profile endpoint, not from the token. The token carries authorization, not identity, so a client that was never granted the profile scope learns only the subject id."
      />

      <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm" aria-labelledby="identity-heading">
        <div className="flex items-center gap-4">
          <span className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full bg-[#001E2B] text-lg font-bold text-[#00ED64]">
            {initials(claims)}
          </span>
          <div className="min-w-0">
            <h2 id="identity-heading" className="truncate text-xl font-bold text-[#001E2B]">{who}</h2>
            <p className="mt-0.5 text-sm text-gray-500">
              {roles.length > 0 ? roles.join(', ') : 'No role assigned'} in the {realm || 'unknown'} realm
            </p>
          </div>
        </div>

        {loading && !info && <p className="mt-4 text-xs text-gray-400">Reading your profile…</p>}

        <dl className="mt-5 grid gap-4 border-t border-gray-100 pt-4 sm:grid-cols-2">
          {info?.name && typeof info.name === 'string' && <Fact label="Name" value={info.name} />}
          {username && <Fact label="Preferred username" value={username} />}
          {email && (
            <Fact
              label="Email"
              value={email}
              badge={verified
                ? <span className="inline-flex items-center gap-1 rounded border border-emerald-200 bg-emerald-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-emerald-700">
                    <BadgeCheck size={11} aria-hidden /> Verified
                  </span>
                : <span className="rounded border border-amber-200 bg-amber-50 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-700">
                    Unverified
                  </span>}
            />
          )}
          <Fact label="Subject" value={claims.sub} mono hint="The identifier every record about you is filed under. It never changes, even when your name does." />
          {realm && <Fact label="Realm" value={realm} hint="The population of identities you belong to. A token from one realm means nothing in another." />}
        </dl>
      </section>

      <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm" aria-labelledby="authorization-heading">
        <div className="flex items-center gap-1.5">
          <ShieldCheck size={15} className="text-gray-400" aria-hidden />
          <h2 id="authorization-heading" className="text-xs font-semibold uppercase tracking-wider text-gray-600">What you are allowed to do</h2>
          <Tooltip text="Roles and scopes travel in the token. Each interface checks them against its own rules, so this list is what you may attempt, not what every screen will accept." />
        </div>

        <div className="mt-4 space-y-4">
          <Chips
            label="Roles"
            hint="Assigned to you in this realm. They decide which sections the console offers."
            values={roles}
            empty="No role assigned."
            tone="green"
          />
          <Chips
            label="Scopes"
            hint="What this console asked for at sign-in. Nothing outside them was granted."
            values={scopes}
            empty="No scope granted."
            tone="gray"
          />

          <div>
            <div className="flex items-center gap-1.5">
              <h3 className="text-[10px] uppercase tracking-wider text-gray-400">Entitlements</h3>
              <Tooltip text="Carried only when this application asked for a narrower token than its roles allow. Each entry names a resource and one action allowed on it." />
            </div>
            {entitlements.length === 0
              ? <p className="mt-1 text-sm text-gray-400">This token carries roles rather than individual entitlements.</p>
              : (
                <ul className="mt-2 grid gap-1.5 sm:grid-cols-2">
                  {entitlements.map((entitlement) => {
                    const [resource, action] = entitlement.split(':');
                    return (
                      <li
                        key={entitlement}
                        className="flex items-baseline gap-2 rounded-lg border border-gray-200 bg-gray-50 px-2.5 py-1.5"
                      >
                        <span className="truncate text-xs font-medium text-[#001E2B]">{resource}</span>
                        <span className="ml-auto shrink-0 rounded bg-white px-1.5 py-0.5 font-mono text-[10px] text-gray-600">
                          {action}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              )}
          </div>
        </div>
      </section>

      <section className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm" aria-labelledby="session-heading">
        <div className="flex items-center gap-1.5">
          <h2 id="session-heading" className="text-xs font-semibold uppercase tracking-wider text-gray-600">This session</h2>
          <Tooltip text="Where the token came from, who it is addressed to, and how long it lasts. The authority checks its signature on every call the console makes." />
        </div>
        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
          {claims.iss && <Fact label="Issuer" value={claims.iss} mono hint="The authority that signed the token." />}
          {audience && <Fact label="Audience" value={audience} mono hint="The interfaces the token is addressed to. Any other one must refuse it." />}
          {claims.client_id && <Fact label="Obtained by" value={claims.client_id} mono hint="The registered client that ran the sign-in and holds this token." />}
          {stamp(claims.iat) && <Fact label="Issued" value={stamp(claims.iat)} />}
          {stamp(claims.exp) && <Fact label="Expires" value={stamp(claims.exp)} />}
          {claims.sid && <Fact label="Session" value={claims.sid} mono hint="The sign-in this token belongs to. Ending it ends every token issued under it." />}
        </dl>
      </section>

      <section className="grid gap-4 sm:grid-cols-2" aria-label="Things you own">
        <OwnedLink
          href="/system/credentials/authenticators"
          icon={KeyRound}
          title="Your authenticators"
          description="Devices registered to approve a sign-in for you."
        />
        <OwnedLink
          href="/system/applications"
          icon={Layers}
          title="Authorized applications"
          description="Applications you allowed to act for you, and what each was allowed."
        />
      </section>

      <details className="group rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
        <summary className="flex cursor-pointer list-none items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]">
          <ChevronRight size={14} className="text-gray-400 transition-transform group-open:rotate-90" aria-hidden />
          Raw claims
          <Tooltip text="Exactly what the token and the profile endpoint returned, unedited, for an operator who needs to check a claim by name." />
        </summary>
        <div className="mt-4 space-y-4">
          <RawBlock title="Access token claims" data={claims} />
          {info && <RawBlock title="Profile endpoint response" data={info as UserInfo} />}
        </div>
      </details>
    </main>
  );
}

function Fact({ label, value, mono, hint, badge }: {
  label: string;
  value: string;
  mono?: boolean;
  hint?: string;
  badge?: React.ReactNode;
}) {
  return (
    <div className="min-w-0">
      <dt className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-gray-400">
        {label}
        {hint && <Tooltip text={hint} />}
      </dt>
      <dd className="mt-0.5 flex items-center gap-2">
        <span className={`min-w-0 truncate text-gray-800 ${mono ? 'font-mono text-xs' : 'text-sm'}`} title={value}>{value}</span>
        {badge}
      </dd>
    </div>
  );
}

function Chips({ label, hint, values, empty, tone }: {
  label: string;
  hint: string;
  values: string[];
  empty: string;
  tone: 'green' | 'gray';
}) {
  const style = tone === 'green'
    ? 'border-[#00684A]/30 bg-[#00ED64]/10 text-[#00684A]'
    : 'border-gray-200 bg-gray-50 font-mono text-gray-600';
  return (
    <div>
      <div className="flex items-center gap-1.5">
        <h3 className="text-[10px] uppercase tracking-wider text-gray-400">{label}</h3>
        <Tooltip text={hint} />
      </div>
      {values.length === 0
        ? <p className="mt-1 text-sm text-gray-400">{empty}</p>
        : (
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {values.map((value) => (
              <li key={value} className={`rounded border px-2 py-0.5 text-xs font-medium ${style}`}>{value}</li>
            ))}
          </ul>
        )}
    </div>
  );
}

function OwnedLink({ href, icon: Icon, title, description }: {
  href: string;
  icon: typeof KeyRound;
  title: string;
  description: string;
}) {
  return (
    <Link
      href={href}
      className="group flex items-center gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm transition-all hover:border-[#001E2B] hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
    >
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#001E2B]">
        <Icon size={18} className="text-[#00ED64]" aria-hidden />
      </span>
      <span className="min-w-0">
        <span className="block font-semibold text-[#001E2B]">{title}</span>
        <span className="mt-0.5 block text-sm text-gray-500">{description}</span>
      </span>
      <ChevronRight size={16} className="ml-auto shrink-0 text-gray-300 transition-transform group-hover:translate-x-0.5 group-hover:text-[#001E2B]" aria-hidden />
    </Link>
  );
}

function RawBlock({ title, data }: { title: string; data: object }) {
  return (
    <div>
      <p className="mb-1.5 text-[10px] uppercase tracking-wider text-gray-400">{title}</p>
      <JsonView data={data} theme="light" collapsed={2} maxHeight="18rem" fullscreenTitle={title} />
    </div>
  );
}
