import { Db } from 'mongodb';
import { SecurityEventService } from './securityEvent.service';

/**
 * A change to configuration, recorded with what it was BEFORE and what it is now.
 *
 * The gap this closes: administrative changes were recorded inconsistently and never with the
 * previous value. `meta.version` gives a counter, not a value, so "who changed this role from X to
 * Y" was unanswerable unless the individual call site happened to include it, and most did not.
 * PCI DSS 10.2.1.x requires every administrative action and every change to identification and
 * authentication credentials to be recorded; NIST SP 800-53 AU-3 requires the CONTENT to be enough
 * to reconstruct what happened, and a counter is not.
 *
 * ONE function rather than a convention, because a convention is followed at nineteen call sites out
 * of twenty and the twentieth is the one an auditor asks about.
 */

/** What changed, computed here so no caller has to describe its own diff. */
export interface ConfigurationDiff {
  changed: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
}

/**
 * The fields that differ, shallowly, with their old and new values.
 *
 * Shallow on purpose. A deep diff of a nested policy would produce a path list nobody reads, and the
 * question an investigation asks is which ATTRIBUTE moved. The whole old and new values of a changed
 * attribute are kept, so the detail is there without the noise.
 */
export function diffOf(
  before: Record<string, unknown> | null | undefined,
  after: Record<string, unknown> | null | undefined,
  ignore: string[] = ['meta', '_id'],
): ConfigurationDiff {
  const skip = new Set(ignore);
  const keys = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})].filter((key) => !skip.has(key)));

  const changed: string[] = [];
  const from: Record<string, unknown> = {};
  const to: Record<string, unknown> = {};
  for (const key of keys) {
    const left = (before ?? {})[key];
    const right = (after ?? {})[key];
    if (JSON.stringify(left) === JSON.stringify(right)) continue;
    changed.push(key);
    from[key] = left;
    to[key] = right;
  }
  return { changed: changed.sort(), before: from, after: to };
}

export interface ConfigurationChangeInput {
  realmId: string;
  tenantId: string;
  /** What kind of record moved: `policy`, `role`, `resource`, `domain`, `realm`, `credential`. */
  what: string;
  /** Which one. */
  ref: string;
  /** `created`, `updated`, `deleted`, or a verb the surface uses such as `retired`. */
  operation: string;
  /** Who did it. Never inferred: an act nobody can attribute later should not be possible. */
  actorSubjectId: string;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  /** Fields never worth diffing, beyond `meta` and `_id`. */
  ignore?: string[];
}

/**
 * Records one configuration change.
 *
 * Emitted even when nothing moved, and that is deliberate: a no-op is still a decision somebody
 * made, and a trail holding only the changes cannot tell "they reviewed it and left it alone" from
 * "nobody looked". The same argument the grant scope change makes.
 */
export async function recordConfigurationChange(db: Db, input: ConfigurationChangeInput): Promise<void> {
  const diff = diffOf(input.before, input.after, input.ignore);

  await new SecurityEventService(db).record({
    realmId: input.realmId,
    tenantId: input.tenantId,
    category: 'configuration',
    action: `configuration.${input.what}.${input.operation}`,
    outcome: 'success',
    subjectId: input.actorSubjectId,
    target: { type: input.what, ref: input.ref },
    detail: {
      operation: input.operation,
      changed: diff.changed,
      before: diff.before,
      after: diff.after,
      // Stated rather than left to be inferred from an empty `changed`, since the two readings of
      // an empty list are "nothing moved" and "nobody computed it".
      ...(diff.changed.length === 0 ? { note: 'reviewed, nothing changed' } : {}),
    },
  });
}
