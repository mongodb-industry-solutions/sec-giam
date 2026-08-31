import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * The logical agent: what was APPROVED, as distinct from what is running.
 *
 * A two-value model that treats "the agent" and "the process executing right now" as one thing
 * destroys the distinction that matters most here. This record says an agent of this name, at this
 * version, with this configuration, was approved for this purpose by this owner. A workload says a
 * particular container is running, attested, holding a particular credential. One approved agent has
 * many workloads over its life, and an audit record has to be able to name both: "which agent did
 * this" and "which instance of it".
 *
 * The division of responsibility is the other half. This authority owns the IDENTITY lifecycle: an
 * agent exists, it is active, it is suspended, it is retired. Whether it may OPERATE, at what risk
 * class, under which control profile, is governance and belongs to the system that governs it.
 * Deciding both here would make this service the arbiter of business risk, which it has no basis to
 * be, and would put an approval workflow inside an authentication service.
 */
export type AgentLifecycleState = 'proposed' | 'approved' | 'active' | 'suspended' | 'retired';

export interface AgentRecord extends Scoped {
  agentId: string;
  /** The principal this agent authenticates as. An agent is an identity, not a label on one. */
  subjectId: string;
  name: string;
  /** Immutable once approved. A new version is a new record, because it was approved separately. */
  version: string;

  /** The party that runs it. An agent with no owner is the unattributable service account again. */
  owner: {
    kind: 'application' | 'tenant' | 'person' | 'team';
    ref: string;
    displayName?: string;
  };

  /**
   * The party ANSWERABLE for what it does, which is not always the party that runs it.
   *
   * Kept separate deliberately. An operations team may run an agent on behalf of a business owner,
   * and after an incident the question is who was accountable, not who deployed it.
   */
  accountableParty: string;

  /** Why it exists, in the owner's own words. What a reviewer reads first. */
  purpose: string;

  /**
   * A digest of the configuration that was approved.
   *
   * The point of recording it is drift: an agent running with a configuration that does not match
   * what was approved is the ordinary way an approved thing becomes an unapproved thing, and without
   * a digest nobody can tell.
   */
  configurationDigest?: string;
  /** Signed by whoever approved it, where the approval must be verifiable rather than merely stored. */
  signedMetadata?: string;

  /** What it may call. An empty list is an agent that may call nothing, never an unrestricted one. */
  allowedToolIds: string[];

  lifecycleState: AgentLifecycleState;
  meta: Meta;
}

/**
 * Whether this agent may authenticate at all.
 *
 * Note what this does NOT say: nothing here decides whether it may perform a given action. That is
 * the governing system's call, and conflating the two would let an identity service silently become
 * the thing that authorises business risk.
 */
export function canAuthenticate(agent: Pick<AgentRecord, 'lifecycleState'>): boolean {
  return agent.lifecycleState === 'active';
}

/** Whether a tool is one this agent was approved to call. Absence is refusal, never permission. */
export function mayCall(agent: Pick<AgentRecord, 'allowedToolIds'>, toolId: string): boolean {
  return agent.allowedToolIds.includes(toolId);
}
