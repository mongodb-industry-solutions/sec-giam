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
export type IdentityKind = 'human' | 'workload' | 'agent' | 'application' | 'service';

export type LifecycleState = 'pending' | 'active' | 'suspended' | 'deprovisioned';

/** SCIM multi-valued attribute, projected at read time from the stored scalar. */
export interface MultiValued {
  value: string;
  primary?: boolean;
  type?: string;
}

export interface IdentityRecord extends Scoped {
  /** The OIDC `sub`. Reuses the platform's existing login reference so historical rows resolve. */
  subjectId: string;
  userName: string;
  kind: IdentityKind;

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
   * Who is accountable for a non-human principal.
   *
   * The absence of an owner, a lifecycle and an audit trail is what turns service accounts into the
   * permanent, unattributable credentials every audit finds, so a machine identity carries all three.
   */
  owner?: OwnerRef;

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

  meta: Meta;
}

/** The SCIM representation, built from the stored scalars. */
export function toScimEmails(identity: Pick<IdentityRecord, 'primaryEmail' | 'emails'>): MultiValued[] {
  const primary = identity.primaryEmail ? [{ value: identity.primaryEmail, primary: true, type: 'work' }] : [];
  return [...primary, ...(identity.emails ?? [])];
}

export function toScimPhoneNumbers(identity: Pick<IdentityRecord, 'primaryPhone' | 'phoneNumbers'>): MultiValued[] {
  const primary = identity.primaryPhone ? [{ value: identity.primaryPhone, primary: true, type: 'mobile' }] : [];
  return [...primary, ...(identity.phoneNumbers ?? [])];
}

/** Whether this principal may authenticate at all, before any credential is checked. */
export function canAuthenticate(identity: Pick<IdentityRecord, 'active' | 'lifecycleState'>): boolean {
  return identity.active && identity.lifecycleState === 'active';
}
