'use client';
import { PLATFORM_ENVIRONMENTS, baseUrlProblem, type ClientBaseUrls } from '../lib/clients';

/**
 * Where this application answers, one row per environment.
 *
 * Three fixed rows rather than a list a person adds to: the set of environments is the platform's and
 * not the application's, so a free list could only ever produce a name nothing resolves against. It
 * sits beside the logo field because that is what these addresses bind, and the hint says so: the
 * value of filling them in is invisible otherwise.
 *
 * Addresses are OPTIONAL, each one on its own. An application that is not deployed to an environment
 * leaves that row empty, which reads as "not published here" rather than as a missing address, and
 * that is exactly how the authority treats it.
 */
export function EnvironmentUrlsEditor({
  values,
  onChange,
}: {
  values: ClientBaseUrls;
  onChange: (values: ClientBaseUrls) => void;
}) {
  return (
    <div className="space-y-1.5">
      {PLATFORM_ENVIRONMENTS.map((environment) => {
        const value = values[environment] ?? '';
        const problem = value.trim() ? baseUrlProblem(value) : null;
        return (
          <div key={environment}>
            <div className="flex items-center gap-2">
              <span className="w-24 shrink-0 text-xs text-gray-500">{environment}</span>
              <input
                value={value}
                onChange={(event) => onChange({ ...values, [environment]: event.target.value })}
                placeholder={environment === 'development' ? 'http://localhost:3000' : 'https://app.example'}
                className={`flex-1 rounded-lg border px-2.5 py-2 font-mono text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-[#001E2B]/10 ${
                  problem ? 'border-red-300' : 'border-gray-200 focus:border-[#001E2B]'
                }`}
              />
            </div>
            {problem && <p className="ml-[6.5rem] mt-1 text-xs text-red-600">{problem}</p>}
          </div>
        );
      })}
    </div>
  );
}
