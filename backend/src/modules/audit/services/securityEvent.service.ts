import { Db } from 'mongodb';
import { createHash } from 'crypto';
import { SECURITY_EVENT_COLLECTION } from '../../../shared/models/collections';
import { SecurityEventRecord } from '../models/securityEvent.model';

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

/**
 * The correlator that groups one flow.
 *
 * Derived from the state parameter rather than storing it: the state is a value the client chose and
 * may be guessable, and a trail does not need it, only the ability to say two records belong to the
 * same flow.
 */
export function hashState(state: string): string {
  return `flow:${createHash('sha256').update(state).digest('hex').slice(0, 16)}`;
}

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
  policyVersion?: string;
  decision?: 'allow' | 'deny';
  enforcementResult?: string;
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
      const event: SecurityEventRecord = {
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
      await this.db.collection<SecurityEventRecord>(SECURITY_EVENT_COLLECTION).insertOne(event);
    } catch {
      // Deliberately swallowed. See above.
    }
  }

  /**
   * Queries the trail.
   *
   * Range-first, because a time series is organised that way and a query that ignores it scans. The
   * caller's authority is enforced by the controller: this service answers what it is asked, and a
   * filter applied by a client after the fact is not an access control.
   */
  async query(filter: {
    realmId: string;
    from?: Date;
    to?: Date;
    subjectId?: string;
    clientId?: string;
    action?: string;
    outcome?: 'success' | 'failure';
    correlationId?: string;
    limit?: number;
  }): Promise<SecurityEventRecord[]> {
    const query: Record<string, unknown> = { realmId: filter.realmId };
    if (filter.from || filter.to) {
      query.ts = {
        ...(filter.from ? { $gte: filter.from } : {}),
        ...(filter.to ? { $lte: filter.to } : {}),
      };
    }
    if (filter.subjectId) query['meta.subjectId'] = filter.subjectId;
    if (filter.clientId) query['meta.clientId'] = filter.clientId;
    if (filter.action) query.action = filter.action;
    if (filter.outcome) query.outcome = filter.outcome;
    if (filter.correlationId) query.correlationId = filter.correlationId;

    return this.db
      .collection<SecurityEventRecord>(SECURITY_EVENT_COLLECTION)
      .find(query, { projection: { _id: 0 } })
      .sort({ ts: -1 })
      .limit(Math.min(filter.limit ?? 100, 500))
      .toArray();
  }
}
