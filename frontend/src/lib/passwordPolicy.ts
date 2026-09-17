import { callApi } from './console';

/**
 * The rules a new password must satisfy, as a checklist a form can render while somebody types.
 *
 * The POLICY is read from the authority (`GET /credentials/password/policy`), never hardcoded: a
 * realm that raises its minimum length would otherwise leave every form here telling people the old
 * number. What is mirrored is only the EVALUATION, and it mirrors `checkPassword` in
 * `backend/src/modules/realm/models/domain.model.ts` rule for rule, including the deliberately broad
 * symbol class. Keep the two in step; the authority remains the one that decides, and this exists so
 * a person is told what is missing before submitting rather than after being refused.
 */

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
  historyDepth: number;
}

/** One rule, its wording, and whether what has been typed so far satisfies it. */
export interface PasswordRule {
  key: string;
  label: string;
  met: boolean;
}

export async function loadPasswordPolicy(): Promise<PasswordPolicy | null> {
  const answer = await callApi<{ policy: PasswordPolicy | null }>('/credentials/password/policy', {
    subject: 'the password policy',
  });
  return answer?.policy ?? null;
}

/**
 * The checklist for a candidate password.
 *
 * `against` carries the values only this form knows about: the confirmation, and the current
 * password where there is one. They are rules the authority enforces too (it answers 400 for
 * either), so they belong in the same list rather than in a separate error line below it.
 *
 * Every rule is returned whatever its state, because a checklist that only shows what is still
 * wrong tells nobody what is already right.
 */
export function evaluatePassword(
  policy: PasswordPolicy | null,
  password: string,
  against: { confirmation?: string; currentPassword?: string } = {},
): PasswordRule[] {
  const rules: PasswordRule[] = [];

  if (policy) {
    rules.push({
      key: 'minLength',
      label: `At least ${policy.minLength} characters`,
      met: password.length >= policy.minLength,
    });
    if (policy.requireUppercase) {
      rules.push({ key: 'requireUppercase', label: 'An upper-case letter', met: /[A-Z]/.test(password) });
    }
    if (policy.requireNumber) {
      rules.push({ key: 'requireNumber', label: 'A number', met: /[0-9]/.test(password) });
    }
    if (policy.requireSymbol) {
      rules.push({
        key: 'requireSymbol',
        label: 'A symbol',
        met: /[^A-Za-z0-9\s]/.test(password),
      });
    }
  }

  if (against.currentPassword !== undefined) {
    rules.push({
      key: 'differs',
      label: 'Different from your current password',
      // Nothing typed yet is not the same as satisfied, so an empty box leaves this unmet.
      met: password.length > 0 && password !== against.currentPassword,
    });
  }
  if (against.confirmation !== undefined) {
    rules.push({
      key: 'confirmation',
      label: 'Matches the confirmation',
      met: password.length > 0 && password === against.confirmation,
    });
  }

  return rules;
}

export const allMet = (rules: PasswordRule[]) => rules.every((rule) => rule.met);
