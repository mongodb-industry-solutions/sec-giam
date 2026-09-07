'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowRight, LayoutGrid } from 'lucide-react';
import { SignInPanel, type SignedIn } from '../../components/SignInPanel';
import { SectionHeader } from '../../components/SectionHeader';
import { Tooltip } from '../../components/Tooltip';
import { callApi, currentClaims, displayName, isExpired, startOfToday, when, type Claims } from '../../lib/console';
import { visibleSections } from '../../lib/consoleNav';
import { useUserInfo } from '../../lib/profile';
import { CONSOLE_CLIENT_ID, storedRealm } from '../../lib/session';
import { BRAND } from '../../config/brand';

/**
 * Application Mode: the authority used as a product, by a person who signed in.
 *
 * Distinct from the sign-in page, which exists for relying parties to redirect to, and from the
 * operations surface, which holds an administrative credential rather than anybody's identity. What
 * this screen shows is what the SIGNED-IN principal can reach, chosen from their own claims.
 */

interface Count {
  value: number;
  noun: string;
}

/**
 * A card's live figure, or nothing.
 *
 * A count that cannot be read is left off the card rather than shown as an error: the card's job is
 * to open the section, and the section itself is where a failure to read it belongs.
 */
function useCount(enabled: boolean, load: () => Promise<Count>): Count | null {
  const [count, setCount] = useState<Count | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    load().then((value) => { if (live) setCount(value); }).catch(() => {});
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled]);
  return count;
}

export default function ConsoleOverviewPage() {
  const [claims, setClaims] = useState<Claims | null>(null);
  const [checked, setChecked] = useState(false);
  const [realm, setRealm] = useState('');
  // The heading names the person, which the token cannot do on its own.
  useUserInfo();

  useEffect(() => {
    const found = currentClaims();
    setClaims(found && !isExpired(found) ? found : null);
    setRealm(storedRealm());
    setChecked(true);
  }, []);

  function afterSignIn(_signedIn: SignedIn) {
    const found = currentClaims();
    setClaims(found && !isExpired(found) ? found : null);
    setRealm(storedRealm());
  }

  const signedIn = Boolean(claims);
  const sections = visibleSections(claims).filter((section) => section.key !== 'overview');

  const applications = useCount(signedIn, async () => {
    const body = await callApi<{ grants: Array<{ status: string }> }>('/grants', { query: { status: 'active' } });
    return { value: body.grants.length, noun: 'authorized' };
  });
  const credentials = useCount(signedIn, async () => {
    const body = await callApi<{ credentials: Array<{ status: string }> }>('/credentials');
    return { value: body.credentials.filter((c) => c.status === 'active').length, noun: 'enrolled' };
  });
  const elevations = useCount(
    signedIn && sections.some((section) => section.key === 'elevations'),
    async () => {
      const body = await callApi<{ elevations: unknown[] }>('/elevations', { query: { state: 'in-force' } });
      return { value: body.elevations.length, noun: 'in force' };
    },
  );
  const activity = useCount(signedIn, async () => {
    const body = await callApi<{ events: unknown[] }>('/security-events', { query: { from: startOfToday(), limit: 500 } });
    return { value: body.events.length, noun: 'today' };
  });

  const counts: Record<string, Count | null> = {
    applications,
    credentials,
    elevations,
    activity,
  };

  if (!checked) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#001E2B] text-sm text-gray-400">
        Checking your session…
      </main>
    );
  }

  if (!claims) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#001E2B] p-4 sm:p-8">
        {/*
          No `onSignedIn`: the console is a registered client of this authority like any other, and
          runs its OWN authorization code flow after a credential is collected here (`session.ts`'s
          `startConsoleAuthorization`), which is what leaves with a token rather than a session cookie.
          Passing one here takes the panel's OTHER branch, meant for a relying party finishing somebody
          else's request: the credential would be collected and nothing would ever be exchanged for a
          token, so this screen would show itself again looking exactly like it had done nothing.
        */}
        <SignInPanel heading={`${BRAND.full} console`} clientId={CONSOLE_CLIENT_ID} />
        <Link href="/" className="text-xs text-gray-400 transition-colors hover:text-[#00ED64]">
          Back to Mode Selection
        </Link>
      </main>
    );
  }

  return (
    <main className="space-y-6">
      <SectionHeader
        icon={LayoutGrid}
        title={displayName(claims)}
        description={`Signed in to the ${realm || 'unknown'} realm as ${(claims.roles ?? []).join(', ') || 'a principal with no role assigned'}`}
      />

      <section aria-label="Console sections" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {sections.map((section) => {
          const Icon = section.icon;
          const count = counts[section.key];
          return (
            <Link
              key={section.key}
              href={section.path}
              className="group flex flex-col rounded-xl border border-gray-200 bg-white p-5 shadow-sm transition-all hover:border-[#001E2B] hover:shadow-md focus:outline-none focus-visible:ring-2 focus-visible:ring-[#00ED64]"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#001E2B]">
                  <Icon size={19} className="text-[#00ED64]" />
                </div>
                {count && (
                  <div className="text-right">
                    <p className="text-2xl font-bold leading-none text-[#001E2B]">{count.value}</p>
                    <p className="mt-1 text-[10px] uppercase tracking-wider text-gray-400">{count.noun}</p>
                  </div>
                )}
              </div>
              <h2 className="mt-4 flex items-center gap-1.5 font-semibold text-[#001E2B]">
                {section.label}
                <ArrowRight size={14} className="text-gray-300 transition-transform group-hover:translate-x-0.5 group-hover:text-[#001E2B]" aria-hidden />
              </h2>
              <p className="mt-1 text-sm leading-relaxed text-gray-500">{section.description}</p>
            </Link>
          );
        })}
      </section>

      <section className="rounded-xl border border-gray-200 bg-white p-5">
        <div className="flex items-center gap-1.5">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-600">Your token</h2>
          <Tooltip text="The access token this console holds. Every screen here is authorized by it, and the authority checks its signature on each call." />
        </div>
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          {/* The subject id is on the profile screen, where that level of detail belongs. A
              dashboard answers "what can I do here", and an opaque identifier answers nothing. */}
          <Fact label="Issuer" value={claims.iss ?? 'not stated'} mono />
          <Fact label="Scope" value={claims.scope ?? 'not stated'} />
          <Fact label="Expires" value={claims.exp ? when(new Date(claims.exp * 1000).toISOString()) : 'not stated'} />
        </dl>
      </section>
    </main>
  );
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-gray-400">{label}</dt>
      <dd className={`truncate text-gray-700 ${mono ? 'font-mono text-xs' : ''}`} title={value}>{value}</dd>
    </div>
  );
}
