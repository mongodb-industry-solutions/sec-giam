import { Db } from 'mongodb';
import { appendLog } from '../../../shared/services/logBuffer';
import { createHash } from 'crypto';
import { AUDIT_COLLECTION } from '../../../shared/models/collections';
import { AuditRecord } from '../models/audit.model';

/**
 * The identity evidence trail.
 *
 * Only identity evidence. Who authenticated, what was issued, what was delegated, what was revoked.
 * A consuming application's business outcome belongs to that application, and recording it here
 * would create two sources of truth for the same event, each incomplete in a different way.
 *
 * Append only, time series, and never updated. An audit record that can be amended is not evidence.
 */

/** Secrets that must never reach a trail, whatever a caller passes in. */
const REDACTED_KEYS = /^(password|client_secret|secret|token|access_token|refresh_token|code|code_verifier|authorization|assertion|proof)$/i;

/**
 * Removes credential material from anything about to be written.
 *
 * Applied at the SINK rather than at each call site, because a redaction that depends on every
 * caller remembering is a redaction with holes exactly where somebody was in a hurry.
 */
export function redactSecrets(value: unknown, depth = 0): unknown {
  if (depth > 6 || value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((entry) => redactSecrets(entry, depth + 1));
  if (typeof value !== 'object') return value;

  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    output[key] = REDACTED_KEYS.test(key) ? '[redacted]' : redactSecrets(entry, depth + 1);
  }
  return output;
}

/*
 * `hashState` lived here and is gone.
 *
 * It derived a flow correlator from the client's `state` parameter, which is optional, chosen by the
 * client, and was truncated to 64 bits. A flow that omitted `state` was correlated by nothing. The
 * flow now has an identifier this authority allocates, which becomes the ticket's `requestId`, the
 * trail's `correlationId` and the `txn` claim, so one value spans the attempt and every token.
 *
 * Deleted rather than left unused: a function still named for correlating a flow is a function
 * somebody reaches for.
 */

/** Hashed, never raw: a trail is not a place to accumulate personal data. */
export function hashIp(value: string | undefined): string | undefined {
  return value ? createHash('sha256').update(value).digest('hex').slice(0, 32) : undefined;
}

/**
 * Turns a failure into a cause worth recording.
 *
 * The cause is what makes a trail useful afterwards: "the token endpoint refused" says nothing,
 * while "the code was replayed" is an incident and "the verifier did not match" is a client bug.
 */
export function classifyFailure(error: string, description?: string): string {
  const text = `${error} ${description ?? ''}`.toLowerCase();
  if (text.includes('already been used')) return 'code_replayed';
  if (text.includes('code_verifier')) return 'pkce_mismatch';
  if (text.includes('redirect_uri')) return 'redirect_uri_mismatch';
  if (text.includes('expired')) return 'expired';
  if (text.includes('client_secret') || error === 'invalid_client') return 'client_authentication_failed';
  if (text.includes('scope')) return 'scope_not_permitted';
  if (text.includes('realm')) return 'unknown_realm';
  return error;
}

export interface RecordEventInput {
  realmId: string;
  tenantId: string;
  action: string;
  outcome: 'success' | 'failure';
  category?: string;
  subjectId?: string;
  clientId?: string;
  correlationId?: string;
  cause?: string;
  detail?: Record<string, unknown>;
  target?: { type: string; ref: string };
  ipHash?: string;

  /**
   * Who else is entitled to see this event.
   *
   * For the case the actor is not the only person the act concerns: one owner of an application adding
   * or removing another changed who may administer something the remaining owners own, and a trail
   * they cannot read is a trail that does not tell them. Passed by the recording call site, because
   * only it knows who held that standing at that moment.
   */
  stakeholderSubjectIds?: string[];

  /**
   * The accountability chain.
   *
   * The trail has to answer, for any action: which human authorised it, which logical agent performed
   * it, which runtime executed it, which tool was called, which policy version allowed it and what
   * happened. Each of those is a separate field because collapsing any two of them loses exactly the
   * distinction an investigation needs.
   */
  principalSubjectId?: string;
  agentId?: string;
  workloadSpiffeId?: string;
  delegationId?: string;
  transactionId?: string;
  toolId?: string;
  normalizedAction?: string;
  policyVersion?: number;
  decision?: 'allow' | 'deny';
  enforcementResult?: string;
}

/**
 * How the trail is doing, so a lost write is visible rather than merely absent.
 *
 * A counter rather than a stored record: the one thing that certainly cannot be relied on when the
 * audit collection is unwritable is writing to the audit collection. Exposed on the health surface,
 * which is what turns "PCI DSS 10.7 requires detecting audit log failures" from a claim into a
 * check somebody can run.
 *
 * Process-local and reset by a restart. That is a real limitation and it is the right trade: the
 * alternative is durable state on the path that is failing.
 */
export const trailWrites = {
  written: 0,
  failed: 0,
  lastFailureAt: undefined as string | undefined,
  lastFailureCause: undefined as string | undefined,
};

/** Whether the trail is currently trustworthy. Any failure at all degrades it: evidence is not sampled. */
export function trailHealth(): { healthy: boolean; written: number; failed: number; lastFailureAt?: string } {
  return {
    healthy: trailWrites.failed === 0,
    written: trailWrites.written,
    failed: trailWrites.failed,
    ...(trailWrites.lastFailureAt ? { lastFailureAt: trailWrites.lastFailureAt } : {}),
  };
}

/** What may be asked of the trail. Named so a count and a read take the same shape. */
export interface AuditQuery {
  realmId: string;
  from?: Date;
  to?: Date;
  subjectId?: string;
  /**
   * Narrows to what one person is entitled to: their own events, plus the ones recorded naming them
   * as a stakeholder. Never widened by a query parameter the caller controls.
   */
  subjectIdOrStakeholder?: string;
  clientId?: string;
  action?: string;
  outcome?: 'success' | 'failure';
  correlationId?: string;
  /**
   * Whether a PERSON drove the act or an application acted for them.
   *
   * `principalSubjectId` is written only when an application obtained a token on somebody's behalf,
   * so its presence is the distinction. The console derived this in the browser from the same field,
   * which meant the filter existed on a screen and not on the API.
   */
  actor?: 'person' | 'application';
  /** Only the events the caller did NOT cause but is entitled to see. */
  stakeholderOnly?: string;
  offset?: number;
  limit?: number;
}

export class SecurityEventService {
  constructor(private readonly db: Db) {}

  /**
   * Records one event.
   *
   * Never throws into its caller. A trail that can fail an authentication is a trail that will be
   * removed from the authentication path the first time it does, and then there is no trail at all.
   */
  async record(input: RecordEventInput): Promise<void> {
    try {
      // Deduplicated, and the actor is dropped: they already see the event through their own subject,
      // and listing them twice would make an empty list and a self-only list look different.
      const stakeholders = [...new Set(input.stakeholderSubjectIds ?? [])]
        .filter((subject) => Boolean(subject) && subject !== input.subjectId);

      const event: AuditRecord = {
        ts: new Date(),
        realmId: input.realmId,
        tenantId: input.tenantId,
        meta: {
          realmId: input.realmId,
          tenantId: input.tenantId,
          category: input.category ?? 'authentication',
          ...(input.clientId ? { clientId: input.clientId } : {}),
          ...(input.subjectId ? { subjectId: input.subjectId } : {}),
        },
        action: input.action,
        outcome: input.outcome,
        ...(input.cause ? { cause: input.cause } : {}),
        ...(input.correlationId ? { correlationId: input.correlationId } : {}),
        ...(input.detail ? { detail: redactSecrets(input.detail) as Record<string, unknown> } : {}),
        ...(input.target ? { target: input.target } : {}),
        ...(stakeholders.length > 0 ? { stakeholderSubjectIds: stakeholders } : {}),
        // Written only when present, so an event that has nothing to say about the chain does not
        // carry a row of empty fields implying it was checked and found absent.
        ...(input.principalSubjectId ? { principalSubjectId: input.principalSubjectId } : {}),
        ...(input.agentId ? { agentId: input.agentId } : {}),
        ...(input.workloadSpiffeId ? { workloadSpiffeId: input.workloadSpiffeId } : {}),
        ...(input.delegationId ? { delegationId: input.delegationId } : {}),
        ...(input.transactionId ? { transactionId: input.transactionId } : {}),
        ...(input.toolId ? { toolId: input.toolId } : {}),
        ...(input.normalizedAction ? { normalizedAction: input.normalizedAction } : {}),
        ...(input.policyVersion ? { policyVersion: input.policyVersion } : {}),
        ...(input.decision ? { decision: input.decision } : {}),
        ...(input.enforcementResult ? { enforcementResult: input.enforcementResult } : {}),
        actor: {
          ...(input.subjectId ? { subjectId: input.subjectId } : {}),
          ...(input.clientId ? { clientId: input.clientId } : {}),
          ...(input.ipHash ? { ipHash: input.ipHash } : {}),
        },
      };
      await this.db.collection<AuditRecord>(AUDIT_COLLECTION).insertOne(event);
      trailWrites.written += 1;
    } catch (err) {
      /**
       * Still not thrown, and now not silent either.
       *
       * The availability argument above is sound: a trail that can fail an authentication is a
       * trail that gets removed from the authentication path the first time it does. But it was
       * swallowed with no log line, no counter and no retry, so a failure was undetectable BY
       * CONSTRUCTION. PCI DSS 10.7 requires detection of audit log failures, and on a full disk or
       * a dropped connection the evidence disappeared and nobody learned.
       *
       * There is a second reason this matters more here than it would elsewhere: an audit write can
       * never be atomic with the state change it records, because a time series collection cannot be
       * written inside a transaction. The trail is structurally best-effort, so detecting a lost
       * write is the only control there is.
       */
      trailWrites.failed += 1;
      trailWrites.lastFailureAt = new Date().toISOString();
      trailWrites.lastFailureCause = err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200);
      // Through the log buffer, so it reaches the operations panel and not only stderr.
      appendLog(
        `[${trailWrites.lastFailureAt}] ERROR audit trail write failed (${trailWrites.failed} total): `
        + `${input.action} ${input.outcome} — ${trailWrites.lastFailureCause}`,
      );
    }
  }

  /**
   * Queries the trail.
   *
   * Range-first, because a time series is organised that way and a query that ignores it scans. The
   * caller's authority is enforced by the controller: this service answers what it is asked, and a
   * filter applied by a client after the fact is not an access control.
   */
  /**
   * One filter, built once, so a count and a read can never disagree about what matches.
   *
   * Separated when paging arrived: a caller paging against a total computed from a different filter
   * than the page is paging through a number that means nothing.
   */
  private toQuery(filter: AuditQuery): Record<string, unknown> {
    const query: Record<string, unknown> = { realmId: filter.realmId };
    if (filter.from || filter.to) {
      query.ts = {
        ...(filter.from ? { $gte: filter.from } : {}),
        ...(filter.to ? { $lte: filter.to } : {}),
      };
    }
    if (filter.subjectId) query['meta.subjectId'] = filter.subjectId;
    if (filter.subjectIdOrStakeholder) {
      query.$or = [
        { 'meta.subjectId': filter.subjectIdOrStakeholder },
        { stakeholderSubjectIds: filter.subjectIdOrStakeholder },
      ];
    }
    if (filter.clientId) query['meta.clientId'] = filter.clientId;
    if (filter.action) query.action = filter.action;
    if (filter.outcome) query.outcome = filter.outcome;
    if (filter.correlationId) query.correlationId = filter.correlationId;
    if (filter.actor === 'application') query.principalSubjectId = { $exists: true };
    if (filter.actor === 'person') query.principalSubjectId = { $exists: false };
    if (filter.stakeholderOnly) {
      // Entitled to see it without having caused it, which is a different question from "mine".
      query.stakeholderSubjectIds = filter.stakeholderOnly;
      query['meta.subjectId'] = { $ne: filter.stakeholderOnly };
      delete query.$or;
    }
    return query;
  }

  /**
   * How many events match, so a caller can page against something real.
   *
   * The console computed `totalPages` from the length of the batch it had fetched, which meant the
   * last page was always the one in hand and there was no way to reach anything beyond the limit.
   */
  async count(filter: AuditQuery): Promise<number> {
    return this.db.collection<AuditRecord>(AUDIT_COLLECTION).countDocuments(this.toQuery(filter));
  }

  async query(filter: AuditQuery): Promise<AuditRecord[]> {
    return this.db
      .collection<AuditRecord>(AUDIT_COLLECTION)
      .find(this.toQuery(filter), { projection: { _id: 0 } })
      /**
       * A TIEBREAK, and it is not cosmetic.
       *
       * Sorting by `ts` alone is not a total order: security events arrive in bursts around a
       * sign-in and many share a millisecond, so the order among ties is whatever the engine
       * returns. That is harmless when reading one page and wrong the moment paging exists, because
       * two requests can order the ties differently and an event then appears on both pages or on
       * neither. On an evidence trail, "or on neither" means an auditor paging through misses one.
       *
       * `_id` is unique per measurement, so `{ts, _id}` is total. It is still projected away: it is
       * an ordering key here and not something a caller needs.
       */
      .sort({ ts: -1, _id: -1 })
      .skip(filter.offset ?? 0)
      .limit(Math.min(filter.limit ?? 100, 500))
      .toArray();
  }
}
