'use client';

import { Check, X } from 'lucide-react';
import { PasswordRule } from '../lib/passwordPolicy';

/**
 * The policy as a live checklist: a green tick for every rule met, a red cross for every one still
 * missing.
 *
 * Shared by the self-service change and the administrative reset, because both are checked against
 * the same policy by the same authority and a person reading one should not learn a different set of
 * rules from the other.
 *
 * Announced politely (`aria-live="polite"`) and each state also carries a word, not colour alone: a
 * checklist that says "missing" only in red says nothing to anybody who cannot see red.
 */
export function PasswordRules({ rules, className = '' }: { rules: PasswordRule[]; className?: string }) {
  if (rules.length === 0) return null;

  return (
    <div className={className}>
      <p className="text-[10px] uppercase tracking-wider text-gray-400">This realm requires</p>
      <ul className="mt-1.5 space-y-1" aria-live="polite">
        {rules.map((rule) => (
          <li key={rule.key} className="flex items-center gap-1.5 text-xs">
            {rule.met
              ? <Check size={13} className="shrink-0 text-emerald-600" aria-hidden />
              : <X size={13} className="shrink-0 text-red-600" aria-hidden />}
            <span className={rule.met ? 'text-emerald-700' : 'text-gray-600'}>{rule.label}</span>
            <span className="sr-only">{rule.met ? '(met)' : '(still missing)'}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
