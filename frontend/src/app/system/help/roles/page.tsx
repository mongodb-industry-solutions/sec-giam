'use client';

import Link from 'next/link';
import { ArrowRight, ShieldHalf } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { AUTHORITY_ROLE_GUIDE } from '../../../../config/authorityRoleGuide';

/**
 * The directory of roles over the authority itself, plus the customer.
 *
 * Short, because most roles in the platform administer an application and hold nothing here. Saying that
 * out loud matters: a reader who cannot find their own role on this page should learn that this is
 * expected rather than conclude the page is incomplete.
 *
 * The customer is the exception and is listed deliberately. It holds no permission either, but unlike an
 * analyst it is a role people actually sign in to this console with, and what it may do here (its own
 * profile, factors, sessions and consents) is a question the page was being asked and did not answer.
 */

export default function AuthorityHelpRoles() {
  return (
    <div className="space-y-5">
      <SectionHeader
        icon={ShieldHalf}
        title="Roles"
        description="Who may administer this authority, what anybody signed in may do regardless, and the reasoning behind every line neither may cross."
        info={
          <>
            These are the roles with permissions over the authority’s own objects, and the customer, which has none.
            It is listed because holding no permission is not the same as having no standing: anybody signed in may
            read their own record, manage their own factors, end their own sessions and withdraw their own consents.
            The remaining application roles are absent rather than listed as empty: an analyst, an investigator or a
            merchant officer administers an application and holds nothing here.
          </>
        }
      />

      <div className="space-y-3">
        {AUTHORITY_ROLE_GUIDE.map((role) => (
          <Link
            key={role.id}
            href={`/system/help/roles/${role.id}`}
            className="group flex items-start gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm transition hover:border-[#00ED64] focus:outline-none focus-visible:border-[#00ED64]"
          >
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#001E2B]">
              <role.icon size={18} className="text-[#00ED64]" />
            </span>
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-sm font-semibold text-[#001E2B]">{role.label}</p>
                <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 font-mono text-[10px] text-gray-500">
                  {role.id}
                </span>
              </div>
              <p className="text-xs leading-relaxed text-gray-600">{role.headline}</p>
              <p className="text-xs leading-relaxed text-gray-600">
                <span className="font-semibold text-[#001E2B]">Cannot:</span> {role.cannot[0].what.toLowerCase()}.
              </p>
            </div>
            <ArrowRight size={15} className="mt-0.5 shrink-0 text-gray-300 transition group-hover:translate-x-0.5 group-hover:text-[#00684A]" />
          </Link>
        ))}
      </div>
    </div>
  );
}
