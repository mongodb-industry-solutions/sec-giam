'use client';
import { useEffect, useState } from 'react';
import { Check, Copy, ExternalLink, Globe } from 'lucide-react';
import { API_PUBLIC_URL } from '../lib/env';
import { privateApiBase } from '../lib/deploymentInfo';

/**
 * Where a relying party reaches this realm, for whoever is wiring up the application being viewed.
 *
 * Every value here is read off the SAME registration, so a person integrating an application never
 * has to go find these addresses in a separate document that can drift from what was actually
 * registered. Grouped public and private the same way the merchant's own SSO page grouped them,
 * before that page's identity moved here: a browser can only ever reach the public origin, so
 * Authorize and the end-session endpoint are shown there regardless of which side is selected, while
 * the rest (token, introspection, revocation, JWKS, discovery) answer equally to a caller inside the
 * cluster, which is the one that should use the private address when one is configured.
 */
export function IntegrationUrls({ realm, grantTypes }: { realm: string; grantTypes: string[] }) {
  const [scope, setScope] = useState<'public' | 'private'>('public');
  const [privateBase, setPrivateBase] = useState<string | null>(null);

  useEffect(() => { void privateApiBase().then(setPrivateBase); }, []);

  const interactive = grantTypes.some((g) => g === 'authorization_code' || g.includes('ciba'));
  const serverToServerBase = scope === 'private' && privateBase ? privateBase : API_PUBLIC_URL;
  const realmPath = `/realms/${realm}`;

  const endpoints: Array<{ label: string; value: string; alwaysPublic?: boolean }> = [
    { label: 'Discovery', value: `${serverToServerBase}${realmPath}/.well-known/openid-configuration` },
    ...(interactive
      ? [{ label: 'Authorize', value: `${API_PUBLIC_URL}${realmPath}/protocol/openid-connect/auth`, alwaysPublic: true }]
      : []),
    { label: 'Token', value: `${serverToServerBase}${realmPath}/protocol/openid-connect/token` },
    { label: 'JWKS', value: `${serverToServerBase}${realmPath}/protocol/openid-connect/certs` },
    ...(interactive
      ? [{ label: 'Userinfo', value: `${serverToServerBase}${realmPath}/protocol/openid-connect/userinfo` }]
      : []),
    { label: 'Introspect', value: `${serverToServerBase}${realmPath}/protocol/openid-connect/token/introspect` },
    { label: 'Revoke token', value: `${serverToServerBase}${realmPath}/protocol/openid-connect/revoke` },
    ...(interactive
      ? [{ label: 'Logout', value: `${API_PUBLIC_URL}${realmPath}/protocol/openid-connect/logout`, alwaysPublic: true }]
      : []),
  ];

  return (
    <section className="rounded-xl border border-gray-200 bg-white p-5">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-gray-600">
          <Globe size={14} className="text-gray-400" aria-hidden />
          Integration
        </h2>
        <div className="inline-flex rounded-lg border border-gray-200 p-0.5 text-xs">
          <button
            type="button"
            onClick={() => setScope('public')}
            className={`rounded-md px-2.5 py-1 transition-colors ${scope === 'public' ? 'bg-[#001E2B] text-white' : 'text-gray-500 hover:text-[#001E2B]'}`}
          >
            Public URLs
          </button>
          <button
            type="button"
            onClick={() => setScope('private')}
            className={`rounded-md px-2.5 py-1 transition-colors ${scope === 'private' ? 'bg-[#001E2B] text-white' : 'text-gray-500 hover:text-[#001E2B]'}`}
          >
            Private URLs
          </button>
        </div>
        <a
          // Always the public address, whichever side is selected: this one is followed by the
          // browser, which cannot reach a private host.
          href={`${API_PUBLIC_URL}${realmPath}/.well-known/openid-configuration`}
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto flex items-center gap-1 text-xs text-gray-400 hover:text-[#001E2B]"
        >
          Open discovery <ExternalLink size={11} aria-hidden />
        </a>
      </div>

      <p className="mt-2 text-xs text-gray-500">
        {scope === 'private'
          ? (privateBase
            ? 'The in-cluster address, for a caller inside the same private network. Authorize and Logout stay public: a browser cannot reach a private host.'
            : 'No private address is configured for this deployment, so the public one is shown.')
          : 'The address a browser, or a caller outside the cluster, reaches this realm at.'}
      </p>

      <dl className="mt-3 divide-y divide-gray-50">
        {endpoints.map((endpoint) => (
          <EndpointRow key={endpoint.label} label={endpoint.label} value={endpoint.value} note={endpoint.alwaysPublic ? 'always public' : undefined} />
        ))}
      </dl>
    </section>
  );
}

function EndpointRow({ label, value, note }: { label: string; value: string; note?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center justify-between gap-3 py-2">
      <span className="w-28 shrink-0 text-xs text-gray-500">
        {label}
        {note && <span className="ml-1 text-[10px] text-gray-400">({note})</span>}
      </span>
      <span className="min-w-0 flex-1 truncate font-mono text-xs text-gray-700">{value}</span>
      <button
        type="button"
        onClick={() => { void navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        className="shrink-0 p-1 text-gray-400 transition-colors hover:text-[#001E2B]"
        title="Copy"
      >
        {copied ? <Check size={13} className="text-green-600" aria-hidden /> : <Copy size={13} aria-hidden />}
      </button>
    </div>
  );
}
