'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import Image from 'next/image';
import { ArrowLeft, Building2, Columns2, Rows3, Sparkles } from 'lucide-react';

import { BRAND } from '../../config/brand';
import teamConfig from '../../config/team.json';

type Layout = 'grid' | 'list';
const LAYOUT_KEY = 'giam.about.layout';

interface TeamContact {
  id: string;
  name: string;
  role: string;
  area?: string;
  ask: string;
  linkedin: string;
  avatarUrl: string;
  qrUrl: string;
}

const FALLBACK: TeamContact[] = teamConfig.contacts;
/** Public IST landing page, shown next to each contact's LinkedIn link. */
const IST_URL = 'https://www.mongodb.com/solutions/industries';

export default function AboutPage() {
  const [contacts] = useState<TeamContact[]>(FALLBACK);
  const [layout, setLayout] = useState<Layout>('list');

  useEffect(() => {
    const saved = localStorage.getItem(LAYOUT_KEY);
    if (saved === 'grid' || saved === 'list') setLayout(saved);
  }, []);

  const chooseLayout = (next: Layout) => {
    setLayout(next);
    localStorage.setItem(LAYOUT_KEY, next);
  };

  return (
    <div className="min-h-screen bg-[#001E2B] text-white">
      {/* Ambient glow, purely decorative */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="about-aurora absolute -top-40 left-1/2 h-[36rem] w-[36rem] -translate-x-1/2 rounded-full bg-[#00ED64]/10 blur-3xl" />
      </div>

      <div className="relative mx-auto w-full max-w-6xl px-4 py-10 sm:px-6 sm:py-14 lg:py-16">
        <Link
          href="/"
          className="inline-flex items-center gap-2 text-sm text-gray-400 transition-colors hover:text-white"
        >
          <ArrowLeft size={16} /> Back to the Portal
        </Link>

        <header className="about-rise mt-8 text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-[#00ED64]/30 bg-[#00ED64]/10 px-3 py-1 text-xs font-medium uppercase tracking-wider text-[#00ED64]">
            <Sparkles size={13} /> MongoDB Industry Solutions Team
          </span>
          <h1 className="mt-5 text-3xl font-bold leading-tight sm:text-4xl lg:text-5xl">
            About <span className="text-[#00ED64]">us</span>
          </h1>
          {/* Who IST is comes first, then how to reach us. The intro stays typographically calm
              so it reads as context rather than a banner. */}
          <p className="mx-auto mt-5 max-w-3xl text-sm leading-relaxed text-gray-400">
            {teamConfig.intro}
          </p>
          <div className="mt-6 flex items-center justify-center gap-2" aria-hidden="true">
            <span className="about-divider" />
            <span className="about-divider-dot" />
            <span className="about-divider" />
          </div>
          <p className="mx-auto mt-6 max-w-3xl text-sm leading-relaxed text-gray-300 sm:text-base">
            These are the main contact points for the <span className="text-[#00ED64]">{BRAND.full}</span> ({BRAND.expansion})
            demo, by area. Reach out through your enterprise account or your usual MongoDB channels to book a deeper
            technical conversation, a workshop or a tailored deep dive with us, or to get support on anything you see
            here. You can also scan a QR to connect on LinkedIn and follow the content we publish.
          </p>
        </header>

        <div className="about-rise mt-10 flex items-center justify-between gap-4" style={{ '--about-delay': '80ms' } as React.CSSProperties}>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-gray-400">
            Contacts <span className="text-gray-400">({contacts.length})</span>
          </h2>
          {/* Layout switch: only meaningful where two columns fit */}
          <div className="hidden items-center gap-1 rounded-lg border border-gray-700 bg-white/5 p-1 lg:flex">
            <button
              type="button"
              onClick={() => chooseLayout('grid')}
              aria-pressed={layout === 'grid'}
              title="Two columns"
              className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                layout === 'grid' ? 'bg-[#00ED64] text-[#001E2B]' : 'text-gray-400 hover:text-white'
              }`}
            >
              <Columns2 size={14} /> 2 columns
            </button>
            <button
              type="button"
              onClick={() => chooseLayout('list')}
              aria-pressed={layout === 'list'}
              title="Single column"
              className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                layout === 'list' ? 'bg-[#00ED64] text-[#001E2B]' : 'text-gray-400 hover:text-white'
              }`}
            >
              <Rows3 size={14} /> 1 column
            </button>
          </div>
        </div>

        <ul
          className={`mt-5 grid gap-5 ${
            layout === 'grid' ? 'sm:grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'
          }`}
        >
          {contacts.map((c, i) => (
            <li
              key={c.id}
              className="about-rise"
              style={{ '--about-delay': `${140 + i * 90}ms` } as React.CSSProperties}
            >
              <ContactCard contact={c} wide={layout === 'list'} />
            </li>
          ))}
        </ul>

        <p className="mt-12 text-center text-xs text-gray-400">
          v{process.env.NEXT_PUBLIC_APP_VERSION ?? '0.0.0'} · MongoDB Industry Solutions Team
        </p>
      </div>
    </div>
  );
}

// lucide-react carries no brand marks, so the LinkedIn glyph is inlined.
function LinkedInIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M20.45 20.45h-3.55v-5.57c0-1.33-.03-3.04-1.85-3.04-1.85 0-2.13 1.45-2.13 2.94v5.67H9.37V9h3.41v1.56h.05c.47-.9 1.63-1.85 3.37-1.85 3.6 0 4.26 2.37 4.26 5.45v6.29zM5.34 7.43a2.06 2.06 0 1 1 0-4.13 2.06 2.06 0 0 1 0 4.13zm1.78 13.02H3.56V9h3.56v11.45zM22.22 0H1.77C.79 0 0 .77 0 1.73v20.54C0 23.22.79 24 1.77 24h20.45c.98 0 1.78-.78 1.78-1.73V1.73C24 .77 23.2 0 22.22 0z" />
    </svg>
  );
}

function ContactCard({ contact, wide }: { contact: TeamContact; wide: boolean }) {
  const profileUrl = `https://www.linkedin.com/in/${contact.linkedin}`;
  return (
    <article className="group flex h-full flex-col gap-5 rounded-2xl border border-gray-700/70 bg-white/[0.04] p-5 transition-all duration-300 hover:-translate-y-1 hover:border-[#00ED64]/50 hover:bg-[#00ED64]/[0.06] hover:shadow-xl hover:shadow-[#00ED64]/5 sm:flex-row sm:p-6">
      <div className="flex shrink-0 items-center gap-4 sm:flex-col sm:items-start">
        <div className="relative h-20 w-20 shrink-0 overflow-hidden rounded-2xl ring-2 ring-[#00ED64]/25 transition-transform duration-300 group-hover:scale-105 sm:h-24 sm:w-24 lg:h-28 lg:w-28">
          <Image src={contact.avatarUrl} alt={contact.name} fill sizes="112px" className="object-cover" />
        </div>
      </div>

      <div className="min-w-0 flex-1">
        <h3 className="text-lg font-bold leading-snug sm:text-xl">{contact.name}</h3>
        <p className="mt-0.5 text-sm font-medium text-[#00ED64]">{contact.role}</p>
        {contact.area ? (
          <span className="mt-2 inline-block rounded-full border border-gray-600 px-2.5 py-0.5 text-[11px] uppercase tracking-wide text-gray-400">
            {contact.area}
          </span>
        ) : null}
        <p className={`mt-3 text-sm leading-relaxed text-gray-400 ${wide ? 'lg:max-w-2xl' : ''}`}>
          <span className="text-gray-400">Ask me about: </span>
          {contact.ask}
        </p>
        {/* Wraps on narrow screens so both links stay tappable */}
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <a
            href={profileUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-gray-700 bg-white/5 px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:border-gray-500 hover:bg-white/10 hover:text-white"
          >
            <LinkedInIcon /> /in/{contact.linkedin}
          </a>
          <a
            href={IST_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg border border-[#00ED64]/30 bg-[#00ED64]/5 px-3 py-1.5 text-xs font-medium text-gray-300 transition-colors hover:border-[#00ED64]/60 hover:bg-[#00ED64]/10 hover:text-white"
          >
            <Building2 size={14} className="text-[#00ED64]" /> MongoDB IST
          </a>
        </div>
      </div>

      {/* QR: the point of the page at a booth, so it stays visible on phones too */}
      <a
        href={profileUrl}
        target="_blank"
        rel="noopener noreferrer"
        title={`Follow ${contact.name} on LinkedIn`}
        className="mx-auto shrink-0 self-center rounded-xl bg-white p-2 transition-transform duration-300 hover:scale-105 sm:mx-0"
      >
        <Image
          src={contact.qrUrl}
          alt={`LinkedIn QR for ${contact.name}`}
          width={132}
          height={132}
          className="h-24 w-24 sm:h-28 sm:w-28 lg:h-32 lg:w-32"
        />
      </a>
    </article>
  );
}
