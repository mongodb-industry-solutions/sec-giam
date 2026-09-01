import type { AuthorizationRequest, AuthorizationDecision, PolicyEvaluator } from '../../../shared/ports';
import { policyEvaluators } from '../../../shared/ports';
import { combineDecisions } from './policyEvaluators';

/**
 * One decision, with the working shown.
 *
 * The combined answer comes from `combineDecisions` and nowhere else, so the deny-wins rule lives in
 * exactly one place and this service cannot quietly reach a different conclusion than the token path
 * does. What it adds is the trace: what each evaluator said on its own, which is the difference
 * between "denied" and "denied by this statement of that policy, because the assurance was too low".
 *
 * A rule that cannot be tested is a rule that gets written wrong and stays wrong, which is why this
 * exists rather than the editor alone.
 */

export interface EvaluatorOpinion {
  name: string;
  /** Null when the evaluator had no opinion, which is not the same as a denial. */
  effect: 'allow' | 'deny' | null;
  reason?: string;
  source?: string;
}

export interface TracedDecision {
  decision: AuthorizationDecision;
  evaluators: EvaluatorOpinion[];
}

export class PolicyDecisionService {
  /** Every registered evaluator, unless a caller names a subset. Tests name one. */
  constructor(private readonly evaluators: PolicyEvaluator[] = policyEvaluators.all()) {}

  async evaluate(request: AuthorizationRequest): Promise<TracedDecision> {
    // Each real evaluator runs ONCE, and the combination rule then sees the memorised answers. Asking
    // twice would be wasteful and, worse, could reach a different answer for a time-of-day condition
    // evaluated either side of an hour boundary.
    const opinions = await Promise.all(
      this.evaluators.map(async (evaluator) => ({
        evaluator,
        decision: await evaluator.evaluate(request),
      })),
    );

    const replay: PolicyEvaluator[] = opinions.map(({ evaluator, decision }) => ({
      name: evaluator.name,
      async evaluate() { return decision; },
    }));

    return {
      decision: await combineDecisions(replay, request),
      evaluators: opinions.map(({ evaluator, decision }) => ({
        name: evaluator.name,
        effect: decision?.effect ?? null,
        ...(decision?.reason ? { reason: decision.reason } : {}),
        ...(decision?.source ? { source: decision.source } : {}),
      })),
    };
  }
}
