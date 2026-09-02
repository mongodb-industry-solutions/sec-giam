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
export interface AuditRecord extends Scoped {
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

  /**
   * Who else may read this event, besides the actor it is recorded against.
   *
   * Written by the code that records the event, never derived when it is read. A read-time derivation
   * would have to re-resolve ownership as it stood at the time, and ownership changes: the person who
   * owned an application yesterday is exactly the person a later read would leave out.
   *
   * This field GRANTS sight, so an entry that does not belong is a disclosure. Only a subject whose
   * own standing the event changed goes in it.
   */
  stakeholderSubjectIds?: string[];

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
