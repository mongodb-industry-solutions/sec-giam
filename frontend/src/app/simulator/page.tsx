import Link from 'next/link';

/**
 * Simulator Mode, not yet built.
 *
 * It exists as a page so the portal has no dead link, and it names the flows it will walk rather than
 * describing itself vaguely: the list below is the set the authority already implements, so it is a
 * plan against real endpoints and not a wish.
 */

const FLOWS = [
  ['Interactive sign-in', 'Password, then authorization code with PKCE, then the token, then introspection and userinfo.'],
  ['Backchannel authentication', 'A decoupled sign-in approved on a second device, with the pending request visible while it waits.'],
  ['Delegation', 'One principal acting for another, with the acting party preserved in the token rather than replaced.'],
  ['Token exchange', 'A token swapped for one scoped to a different audience.'],
  ['Single logout', 'One sign-out ending the session everywhere it was used.'],
];

export default function SimulatorPage() {
  return (
    <main className="mx-auto w-full max-w-3xl p-4 sm:p-6 lg:p-8">
      <h1 className="text-2xl font-semibold text-mongodb-dark">Simulator Mode</h1>
      <p className="mt-2 text-gray-600">
        A guided walk through an authentication flow as a chosen persona, showing the real request and
        the real response at each step. Not built yet.
      </p>

      <ul className="mt-8 space-y-4">
        {FLOWS.map(([name, detail]) => (
          <li key={name} className="rounded-xl border bg-white p-4">
            <p className="font-medium text-mongodb-dark">{name}</p>
            <p className="mt-1 text-sm text-gray-500">{detail}</p>
          </li>
        ))}
      </ul>

      <p className="mt-8 text-sm text-gray-500">
        Every flow above is already implemented by the authority and covered by its own tests; what is
        missing is this screen driving them one step at a time.
      </p>

      <div className="mt-8 flex gap-4 text-sm">
        <Link href="/system" className="underline">Application Mode</Link>
        <Link href="/" className="underline">Back</Link>
      </div>
    </main>
  );
}
