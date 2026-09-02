import { Meta, Scoped, OwnerRef } from '../../../shared/models/base.model';

/**
 * The one principal record.
 *
 * A person and a microservice are the same kind of record here, and that is the design rather than a
 * simplification. A second collection for machines is how the two halves drift, how one of them ends
 * up without an audit trail, and how a capability gets built for people and quietly never built for
 * systems. What differs between them is the authentication method, the assurance required and the
 * lifecycle rules, and all three live in configuration and in ports.
 *
 * SCIM 2.0 core user, plus the attributes a workload needs.
 */

/**
 * Five kinds, from the first version, and immutable once set.
 *
 * The distinction that a two-value model destroys is between an AGENT and a WORKLOAD: a logical agent
 * is what was approved (this owner, this purpose, this configuration digest) and a workload is what is
 * running right now (this container, attested, holding this credential). One approved agent has many
 * workloads over its life, and an audit record has to be able to carry both.
 */
export type PrincipalKind = 'human' | 'workload' | 'agent' | 'application' | 'service';

export type LifecycleState = 'pending' | 'active' | 'suspended' | 'deprovisioned';

/** SCIM multi-valued attribute, projected at read time from the stored scalar. */
export interface MultiValued {
  value: string;
  primary?: boolean;
  type?: string;
}

/** An agent's identity lifecycle. Whether it may OPERATE is the governing system's call, not this one. */
export type AgentLifecycleState = 'proposed' | 'approved' | 'active' | 'suspended' | 'retired';

/**
 * One role a subject holds, as an entry in `principal.roles[]`.
 *
 * Wider than the ADR's minimum of `{roleId, grantedBy, grantedAt, expiresAt?}`, and each addition
 * is a durable fact about the assignment rather than a flow, so it is kept:
 *
 * - `scope` carries cross-realm administration. `kind: 'realm'` is the one value this authority
 *   interprets itself, pointing an assignment at ANOTHER realm so a principal whose identity,
 *   credentials and token stay here may administer there. Dropping it would delete a working
 *   capability, not simplify a shape.
 * - `justification` and `approvalRef` are what make an elevation reviewable after the fact. An
 *   elevation nobody can explain later is an elevation that failed its own purpose.
 * - `ephemeral` marks a time-bound elevation, so a sweep cannot touch a permanent grant.
 *
 * `notBefore` does NOT survive. It existed to encode a pending elevation as an assignment dated far
 * in the future, which `expiresAt` plus a read-time filter now expresses directly.
 */
export interface RoleHolding {
  roleId: string;
  grantedBy?: string;
  grantedAt: string;
  /** Absent means permanent. Present is a JIT elevation, and it needs no second collection. */
  expiresAt?: string;
  scope?: { kind: string; ref: string };
  ephemeral?: boolean;
  justification?: string;
  approvalRef?: string;
  /**
   * Requested and awaiting an approval, granting nothing until it arrives.
   *
   * An explicit flag replaces the previous trick of dating `notBefore` far in the future so that
   * every expiry check would ignore the entry. That worked, and it meant a reader had to know the
   * convention to see that a live-looking assignment granted nothing.
   *
   * A pending request is a FLOW rather than a fact and properly belongs in its own short-lived
   * record. The `elevationRequest` collection that would hold it is deferred, so it is carried here
   * as a flag that fails closed, and it stays a flag until that collection exists.
   */
  pendingApproval?: boolean;
}

/**
 * Whether a holding is in force now.
 *
 * Read-time filtering is the CORRECTNESS mechanism, never the sweeper: a TTL index cannot reach an
 * array element, so an expired entry is present in the document until something removes it. Every
 * effective-roles read goes through here.
 */
export function isHoldingActive(holding: RoleHolding, now: Date = new Date()): boolean {
  // Fails closed on both counts: an unapproved request grants nothing, and so does a lapsed one.
  if (holding.pendingApproval) return false;
  if (!holding.expiresAt) return true;
  return new Date(holding.expiresAt).getTime() > now.getTime();
}

/** The roles in force for a subject, expired entries removed. */
export function activeHoldings(
  principal: Pick<PrincipalRecord, 'roles'>,
  now: Date = new Date(),
): RoleHolding[] {
  return (principal.roles ?? []).filter((holding) => isHoldingActive(holding, now));
}

/**
 * The cap the embedded array is asserted against.
 *
 * Embedding is only safe while the array is bounded. A subject approaching this is a subject whose
 * entitlements should live in policy, so the number is a design signal and not just a guard.
 */
export const MAX_ROLE_HOLDINGS = 100;

export interface PrincipalRecord extends Scoped {
  /** The OIDC `sub`. Reuses the platform's existing login reference so historical rows resolve. */
  subjectId: string;
  userName: string;
  kind: PrincipalKind;

  /**
   * The queryable personal attributes, stored as scalars.
   *
   * Queryable Encryption cannot encrypt a field underneath an array, so the SCIM multi-valued form is
   * projected from these rather than stored. The wire contract still matches the standard; what
   * changes is only where the value physically sits.
   */
  primaryEmail?: string;
  primaryPhone?: string;
  /** Keyed one-way digest of the phone. Carries the unique index that encrypted material cannot. */
  primaryPhoneDigest?: string;
  name?: {
    formatted?: string;
    givenName?: string;
    familyName?: string;
  };

  /** Additional addresses, none of them queryable, so they are safe inside an array. */
  emails?: MultiValued[];
  phoneNumbers?: MultiValued[];

  active: boolean;
  lifecycleState: LifecycleState;
  sessionEpoch: number;

  /** SCIM correlation for inbound provisioning, and the upstream provider when federated. */
  externalId?: string;
  providerId?: string;

  /** Set for `kind: workload`. A workload proves what it is by attestation, not by a stored secret. */
  workload?: {
    attestationIssuer?: string;
    attestationSubject?: string;
    spiffeId?: string;
    trustDomainId?: string;
    attestationState?: 'unverified' | 'attested' | 'failed';
    lastAttestedAt?: string;
  };

  /**
   * Set for `kind: agent`. What was APPROVED, carried by the subject that acts.
   *
   * A sub document rather than a collection, exactly as workload attestation is: a separate record
   * held half a subject whose other half was already here. The approved-versus-running distinction
   * survives in `configurationDigest`, which is the whole point of recording one. An agent running
   * under a configuration that does not match what was approved is the ordinary way an approved
   * thing becomes an unapproved thing, and the audit record names the digest in force at the time.
   *
   * `allowedToolIds` does NOT survive. What an agent may call is an authorization question, so it is
   * policy over a resource of kind tool, decided by the same engine that decides everything else.
   * An allow list here would be a second authorization system with no conditions and no audit.
   */
  agent?: {
    name: string;
    /** Immutable once approved. A new version is a new record, because it was approved separately. */
    version: string;
    /** Why it exists, in the owner's own words. What a reviewer reads first. */
    purpose: string;
    /**
     * The party ANSWERABLE for what it does, which is not always the party that runs it.
     *
     * An operations team may run an agent for a business owner, and after an incident the question
     * is who was accountable, not who deployed it.
     */
    accountableParty: string;
    configurationDigest?: string;
    /** Signed where the approval must be verifiable rather than merely stored. */
    signedMetadata?: string;
    lifecycleState: AgentLifecycleState;
  };

  /**
   * Who is accountable for a non-human principal.
   *
   * The absence of an owner, a lifecycle and an audit trail is what turns service accounts into the
   * permanent, unattributable credentials every audit finds, so a machine identity carries all three.
   */
  owner?: OwnerRef;

  /**
   * The roles this subject holds, embedded.
   *
   * Embedded against the general advice, deliberately and for two reasons. Cardinality is bounded:
   * a subject holds units or tens of roles, because fine grain lives in `policy` and not as rows
   * here. And this is the hottest read in the system: issuing a token needs the subject and its
   * roles, which embedded is one read and referenced is two plus a graph traversal.
   *
   * Two costs are accepted. A TTL index expires whole documents and never array elements, so expiry
   * is enforced by filtering at read time, which is required anyway, plus a sweeper for hygiene. And
   * the inverse question, "who holds role X", needs the multikey index on `{realmId, roles.roleId}`.
   */
  roles?: RoleHolding[];

  /**
   * Binds a principal to the business record they own, for a self-scoped role.
   *
   * An opaque string the authority never resolves: it means something to the application that
   * issued it and nothing here. It travels in the token so a resource server can bind a person to
   * their own records without asking the authority what the reference names.
   */
  accountHolderRef?: string;

  /** Offered on the sign-in roster. Also the only set impersonation may ever target. */
  demoFeatured?: boolean;

  /**
   * A short hint shown beside this persona on the sign-in roster, written by whoever wrote the
   * fixture. Deliberately opaque: it lets a demonstration distinguish two personas holding the same
   * role without this authority learning what a merchant, an account or a case is.
   */
  demoNote?: string;

  meta: Meta;
}

/** The SCIM representation, built from the stored scalars. */
export function toScimEmails(identity: Pick<PrincipalRecord, 'primaryEmail' | 'emails'>): MultiValued[] {
  const primary = identity.primaryEmail ? [{ value: identity.primaryEmail, primary: true, type: 'work' }] : [];
  return [...primary, ...(identity.emails ?? [])];
}

export function toScimPhoneNumbers(identity: Pick<PrincipalRecord, 'primaryPhone' | 'phoneNumbers'>): MultiValued[] {
  const primary = identity.primaryPhone ? [{ value: identity.primaryPhone, primary: true, type: 'mobile' }] : [];
  return [...primary, ...(identity.phoneNumbers ?? [])];
}

/** Whether this principal may authenticate at all, before any credential is checked. */
export function canAuthenticate(identity: Pick<PrincipalRecord, 'active' | 'lifecycleState'>): boolean {
  return identity.active && identity.lifecycleState === 'active';
}
