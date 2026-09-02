'use client';

import Link from 'next/link';
import { ArrowRight, Check, HelpCircle, X } from 'lucide-react';
import { SectionHeader } from '../../../components/SectionHeader';
import { AUTHORITY_ROLE_GUIDE, AUTHORITY_RESOURCES } from '../../../config/authorityRoleGuide';
import { BRAND } from '../../../config/brand';

/**
 * What this authority is, for somebody who arrived at a screen and does not know why it exists.
 *
 * The two lists are deliberately the same length and the same weight. A system explained only by what
 * it does reads as a feature list; the boundary is what makes it comprehensible, because almost every
 * question a reader has here is really a question about where this ends and an application begins.
 */

const DOES = [
  'Authenticates a principal: a person, a service or a workload, by password, by a registered device, or through another authority it federates with.',
  'Issues tokens that say who the holder is, which application they are for, and what they may do.',
  'Holds the roles and the policies that decide the last of those, and resolves them at the moment a token is issued.',
  'Keeps the directory of principals and their lifecycle, and accepts it from an external source of truth over the provisioning protocol.',
  'Registers the applications that may ask for a token, and lets them manage their own registration afterwards.',
  'Records what a person allowed an application to do on their behalf, and lets them withdraw it.',
  'Signs with keys it holds and publishes, rotating them without an outage and retiring them deliberately.',
  'Grants temporary privilege that somebody had to approve and that expires on its own.',
  'Writes an identity trail: who did what, when, and whether it succeeded.',
];

const DOES_NOT = [
  'Holds no accounts, no balances, no cards and no payments. There is no business data here to leak.',
  'Decides nothing about an application’s data. It says what a principal may do; the application enforces it.',
  'Invents no permissions. Each application registers the enforcement points it actually checks, and this authority can only grant those.',
  'Does not implement the payment-services or card-security regimes. It carries the obligations of the institutions that do.',
  'Keeps no account-access consent. That is regulated business data belonging to the institution holding the account, and it must not move here.',
  'Does not re-check a token on every request. Permissions are resolved once, at issuance, and written into the token.',
  'Grants nothing across realms implicitly. Reaching another realm takes an explicit grant that is itself a record.',
];

export default function AuthorityHelpOverview() {
  return (
    <div className="space-y-6">
      <SectionHeader
        icon={HelpCircle}
        title={`What ${BRAND.primary} is`}
        description={`${BRAND.expansion}: the single place this platform decides who somebody is and what they may do.`}
        info={
          <>
            Every application here, the payment provider and the bank alike, stopped deciding that for itself. They
            verify a signature and read a claim. That is why a permission changed here reaches them on the next token
            and not before, and why signing out and back in is sometimes the missing step.
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
          <h2 className="text-sm font-bold text-[#001E2B]">What it answers for</h2>
          <p className="mt-0.5 text-xs text-gray-500">If it is wrong here, it is this authority’s problem.</p>
          <ul className="mt-3 space-y-2.5">
            {DOES.map((item) => (
              <li key={item} className="flex items-start gap-2.5 text-sm leading-relaxed text-gray-700">
                <Check size={15} className="mt-0.5 shrink-0 text-[#00684A]" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </article>

        <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
          <h2 className="text-sm font-bold text-[#001E2B]">What it deliberately is not</h2>
          <p className="mt-0.5 text-xs text-gray-500">Each of these is somebody else’s job, and the boundary is the design.</p>
          <ul className="mt-3 space-y-2.5">
            {DOES_NOT.map((item) => (
              <li key={item} className="flex items-start gap-2.5 text-sm leading-relaxed text-gray-700">
                <X size={15} className="mt-0.5 shrink-0 text-gray-400" />
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </article>
      </div>

      <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-bold text-[#001E2B]">How a decision is actually made</h2>
        <ol className="mt-3 space-y-2.5">
          {[
            'A principal authenticates, by whichever method its realm offers.',
            'The authority reads every role assigned to that principal, including the roles those roles inherit.',
            'It keeps the permissions belonging to the application the token is for, and discards the rest.',
            'Policies run after roles. A conditional statement can deny what a role allowed, and the simulator shows which one decided.',
            'The surviving permissions are written into the token and it is signed.',
            'The application verifies the signature and checks the pair it needs. An absent permission is a refusal, never an unrestricted one.',
          ].map((step, index) => (
            <li key={step} className="flex items-start gap-3 text-sm leading-relaxed text-gray-700">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[#001E2B] text-[10px] font-bold text-[#00ED64]">
                {index + 1}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      </article>

      <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-bold text-[#001E2B]">What this authority governs</h2>
        <p className="mt-0.5 text-xs text-gray-500">
          Its own objects, and the actions each one admits. A permission is a pair, and there is no hierarchy between
          them: managing something does not imply reading it, and reading a key is not the same as rotating one.
        </p>
        <dl className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {AUTHORITY_RESOURCES.map((entry) => (
            <div key={entry.resource} className="min-w-0 rounded-lg border border-gray-100 bg-gray-50 p-2.5">
              <dt className="font-mono text-xs font-semibold text-[#001E2B]">{entry.resource}</dt>
              <dd className="mt-1 text-xs leading-relaxed text-gray-600">{entry.holds}</dd>
              <dd className="mt-1.5 flex flex-wrap gap-1">
                {entry.actions.map((action) => (
                  <span key={action} className="rounded border border-gray-200 bg-white px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
                    {action}
                  </span>
                ))}
              </dd>
            </div>
          ))}
        </dl>
      </article>

      <section className="space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-500">The roles over this authority</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {AUTHORITY_ROLE_GUIDE.map((role) => (
            <Link
              key={role.id}
              href={`/system/help/roles/${role.id}`}
              className="group flex items-start gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm transition hover:border-[#00ED64] focus:outline-none focus-visible:border-[#00ED64]"
            >
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[#001E2B]">
                <role.icon size={16} className="text-[#00ED64]" />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-[#001E2B]">{role.label}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-gray-600">{role.headline}</p>
              </div>
              <ArrowRight size={15} className="mt-0.5 shrink-0 text-gray-300 transition group-hover:translate-x-0.5 group-hover:text-[#00684A]" />
            </Link>
          ))}
        </div>
      </section>
    </div>
  );
}
