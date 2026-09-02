'use client';

import { ScrollText } from 'lucide-react';
import { SectionHeader } from '../../../../components/SectionHeader';
import { STANDARDS, STATUS_LABEL, STATUS_STYLE } from '../../../../config/standardsCatalog';

/**
 * What this authority speaks, and what it merely read.
 *
 * The status on each row is the point of the page. A list that mixes "we implement this" with "we agree
 * with this" cannot be trusted on either, and for an identity authority that distinction is the
 * difference between a client that interoperates and one that does not.
 */

export default function AuthorityHelpStandards() {
  return (
    <div className="space-y-6">
      <SectionHeader
        icon={ScrollText}
        title="Standards"
        description="The protocols this authority speaks, and the regimes it takes into account without implementing."
        info={
          <>
            It speaks the standards rather than resembling them. Where a route has no governing standard, its API
            description says so in those words, so a bespoke endpoint and a conforming one are never mistaken for each
            other. The same honesty applies here: nothing is marked implemented unless a route or a service does it.
          </>
        }
      />

      {STANDARDS.map((group) => (
        <section key={group.group} className="space-y-3">
          <div>
            <h2 className="text-sm font-bold text-[#001E2B]">{group.group}</h2>
            <p className="mt-0.5 max-w-3xl text-xs leading-relaxed text-gray-500">{group.intro}</p>
          </div>

          <ul className="space-y-2">
            {group.entries.map((entry) => (
              <li key={entry.name} className="rounded-xl border border-gray-200 bg-white p-3.5 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-[#001E2B]">{entry.name}</p>
                    <p className="mt-0.5 font-mono text-[11px] text-gray-400">{entry.reference}</p>
                  </div>
                  <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${STATUS_STYLE[entry.status]}`}>
                    {STATUS_LABEL[entry.status]}
                  </span>
                </div>
                <p className="mt-2 text-xs leading-relaxed text-gray-600">{entry.note}</p>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}
