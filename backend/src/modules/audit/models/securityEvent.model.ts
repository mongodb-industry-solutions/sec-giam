import { Scoped } from '../../../shared/models/base.model';

/**
 * One security event.
 *
 * A time-series record: append only, high volume, queried by range. It carries no `meta` version
 * block like the other collections, because it is never amended, and a record that cannot change
 * has no version to track.
 *
 * The fields the agent accountability model needs are present from the start, optional until the
 * phase that populates them. Adding them later would mean rewriting a collection that cannot be
 * altered in place.
 */
export interface SecurityEventRecord extends Scoped {
  ts: Date;
  /** The time-series meta field. Queried by, so it holds what an investigator filters on. */
  meta: {
    realmId: string;
    tenantId: string;
    category: string;
    clientId?: string;
    subjectId?: string;
  };
  action: string;
  outcome: 'success' | 'failure';
  /** Why it failed, classified. "The endpoint refused" is not a cause. */
  cause?: string;
  correlationId?: string;
  detail?: Record<string, unknown>;
  target?: { type: string; ref: string };
  actor: {
    subjectId?: string;
    clientId?: string;
    ipHash?: string;
  };

  // The accountability chain, for the phase that delivers delegation. Declared now because a time
  // series cannot be converted in place, so a field added later means rebuilding the collection.
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
