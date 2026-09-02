'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ArrowLeft, Check, Scale, X } from 'lucide-react';
import { SectionHeader } from '../../../../../components/SectionHeader';
import { Fact } from '../../../../../components/Fact';
import { EmptyState } from '../../../../../components/ResultState';
import { findAuthorityRole, type RoleAbility } from '../../../../../config/authorityRoleGuide';

/**
 * One role, in full.
 *
 * The two columns carry equal weight on purpose. Somebody reading this has usually just been refused
 * something, and the reason beside each withheld line is the answer to whether that was a decision or a
 * defect. A role page that lists only what you may do leaves that question open.
 */

export default function AuthorityRoleDetail() {
  const params = useParams<{ role: string }>();
  const role = findAuthorityRole(String(params.role));

  if (!role) {
    return (
      <div className="space-y-4">
        <BackLink />
        <EmptyState
          title="No such role is described here"
          description="Only the roles with permissions over this authority have a page. A role that administers an application holds nothing here, so there is nothing to describe."
        />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <BackLink />

      <SectionHeader icon={role.icon} title={role.label} description={role.headline} />

      <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-bold text-[#001E2B]">What this role is for</h2>
        <p className="mt-2 text-sm leading-relaxed text-gray-700">{role.purpose}</p>
        <dl className="mt-4 grid gap-3 sm:grid-cols-3">
          <Fact label="Typically held by" value={role.who} />
          <Fact label="Role name" value={role.id} mono />
          <Fact label="Where it comes from">
            <span className="block whitespace-normal text-xs leading-relaxed text-gray-700">{role.origin}</span>
          </Fact>
        </dl>
      </article>

      <div className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
          <h2 className="text-sm font-bold text-[#001E2B]">What it may do</h2>
          <p className="mt-0.5 text-xs text-gray-500">Each line is a permission this authority actually grants.</p>
          <AbilityList items={role.can} tone="can" />
        </article>

        <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
          <h2 className="text-sm font-bold text-[#001E2B]">What it may not do</h2>
          <p className="mt-0.5 text-xs text-gray-500">Each line is a permission deliberately withheld, and why.</p>
          <AbilityList items={role.cannot} tone="cannot" />
        </article>
      </div>

      <article className="rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        <h2 className="text-sm font-bold text-[#001E2B]">Why the role is drawn this way</h2>
        <div className="mt-2 flex items-start gap-2.5">
          <Scale size={15} className="mt-0.5 shrink-0 text-[#00684A]" />
          <p className="text-sm leading-relaxed text-gray-700">{role.separation}</p>
        </div>
      </article>
    </div>
  );
}

function BackLink() {
  return (
    <Link href="/system/help/roles" className="inline-flex items-center gap-1 text-xs font-medium text-[#00684A] hover:underline">
      <ArrowLeft size={13} />
      All roles
    </Link>
  );
}

function AbilityList({ items, tone }: { items: RoleAbility[]; tone: 'can' | 'cannot' }) {
  const Icon = tone === 'can' ? Check : X;
  return (
    <ul className="mt-3 space-y-3">
      {items.map((item) => (
        <li key={item.what} className="flex items-start gap-2.5 border-b border-gray-100 pb-3 last:border-b-0 last:pb-0">
          <Icon size={15} className={`mt-0.5 shrink-0 ${tone === 'can' ? 'text-[#00684A]' : 'text-gray-400'}`} />
          <div className="min-w-0">
            <p className="text-sm font-medium text-[#001E2B]">{item.what}</p>
            <p className="mt-0.5 text-xs leading-relaxed text-gray-600">{item.why}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}
