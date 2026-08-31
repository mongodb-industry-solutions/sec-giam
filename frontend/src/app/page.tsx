import Link from 'next/link';
import Image from 'next/image';
import { BookOpen, Code2, Users } from 'lucide-react';
import { API_PUBLIC_URL } from '../lib/env';
import { BRAND } from '../config/brand';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-[#001E2B] text-white flex flex-col items-center justify-center p-4 sm:p-6">
      <div className="max-w-3xl w-full text-center">
        <div className="text-6xl mb-4"><div className="text-4xl mb-2"> <img src="/app-icon.png" alt={`${BRAND.full} Icon`} className="w-24 h-24 mx-auto" /> </div></div>
        <h1 className="text-2xl sm:text-3xl font-bold mb-2">{BRAND.primary} <span className="text-[#00ED64]">{BRAND.secondary}</span> <span className="text-gray-400 font-medium text-md">({BRAND.expansion})</span></h1>
        <p className="text-[#00ED64] text-lg mb-8 font-medium">
          OAuth 2.0 · OpenID Connect · SCIM 2.0
        </p>
        <p className="text-gray-400 mb-12 max-w-xl mx-auto">
          The identity authority for employees, customers, services, applications, workloads and
          agents. It authenticates and authorises all of them through one pipeline, and it carries no
          vocabulary from the systems it protects.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Link
            href="/simulator"
            className="group block rounded-xl border border-[#00ED64]/30 bg-[#001E2B] hover:bg-[#00ED64]/10 p-6 text-left transition-all"
          >
            <div className="text-3xl mb-3">🎬</div>
            <h2 className="text-xl font-bold mb-2 text-[#00ED64]">Simulator Mode</h2>
            <p className="text-gray-400 text-sm mb-4">
              Flow-driven. Walk a sign-in, a delegation or a token exchange step by step, with the real
              request and the real response at each one.
            </p>
            <span className="inline-block bg-[#00ED64] text-[#001E2B] px-4 py-1.5 rounded font-semibold text-sm group-hover:opacity-90">
              Start Demo
            </span>
          </Link>

          <Link
            href="/system"
            className="group block rounded-xl border border-blue-500/30 bg-[#001E2B] hover:bg-blue-500/10 p-6 text-left transition-all"
          >
            <div className="text-3xl mb-3">🔐</div>
            <h2 className="text-xl font-bold mb-2 text-blue-400">Application Mode</h2>
            <p className="text-gray-400 text-sm mb-4">
              Real sign-in. Administer realms, tenants, identities, roles, policies and credentials, or
              review your own, according to the role you hold.
            </p>
            <span className="inline-block bg-blue-500 text-white px-4 py-1.5 rounded font-semibold text-sm group-hover:opacity-90">
              Sign In
            </span>
          </Link>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-6">
          <a
            href="https://github.com/mongodb-industry-solutions/sec-fsi-pci-dss/wiki"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-gray-700 bg-white/5 hover:border-gray-500 hover:bg-white/10 text-gray-300 hover:text-white text-sm font-medium transition-all"
          >
            <BookOpen size={15} /> Wiki
          </a>
          <a
            href={`${API_PUBLIC_URL}/doc`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-gray-700 bg-white/5 hover:border-gray-500 hover:bg-white/10 text-gray-300 hover:text-white text-sm font-medium transition-all"
          >
            <Code2 size={15} /> API Reference
          </a>

          <Link
            href="/about"
            className="md:col-span-2 inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-[#00ED64]/30 bg-[#00ED64]/5 hover:border-[#00ED64]/60 hover:bg-[#00ED64]/10 text-gray-300 hover:text-white text-sm font-medium transition-all text-center"
          >
            <Users size={15} className="shrink-0 text-[#00ED64]" />
            <span>Take the Next Step: Connect with Our Sector Experts</span>
          </Link>
        </div>

        <p className="mt-3 text-gray-400 text-xs">
          v{process.env.NEXT_PUBLIC_APP_VERSION ?? '0.0.0'} · Identity Authority · OAuth 2.0 · OpenID Connect · SCIM 2.0
        </p>
        <Link
          href="/admin"
          className="mt-8 flex items-center justify-center gap-3 opacity-40 hover:opacity-90 transition-opacity group"
        >
          <div className="overflow-hidden rounded-full w-8 h-8 shrink-0">
            <Image
              src="/mongodb-badge.png"
              alt="MongoDB"
              width={32}
              height={32}
              className="scale-110"
            />
          </div>
          <span className="text-gray-400 text-xs tracking-wide group-hover:text-gray-300 transition-colors">Built on MongoDB Atlas</span>
        </Link>
      </div>
    </div>
  );
}
