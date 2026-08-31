import { Db } from 'mongodb';
import { randomUUID } from 'crypto';
import { ROLE_ASSIGNMENT_COLLECTION, ROLE_COLLECTION } from '../../../shared/models/collections';
import { RoleAssignmentRecord, RoleRecord } from '../../authorization/models/authorization.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { newMeta } from '../../../shared/models/base.model';

/**
 * Temporary authority, granted for a stated reason and taken back automatically.
 *
 * An elevation is a role assignment with an expiry. That is the whole difference, and expressing it
 * as one rather than as its own record is what makes it work: it resolves through the SAME decision
 * point as a permanent assignment, so every check that already honours roles honours an elevation
 * too, with no second code path to keep in step.
 *
 * It replaces a signed capability token that nothing could list, count or revoke. That design was
 * sound in what it did and weak in what it could not do: nobody could answer "who holds elevated
 * access right now", and an elevation granted in error ran to its expiry no matter what anyone
 * decided afterwards. Both are ordinary questions during an incident, and neither had an answer.
 */

const DEFAULT_DURATION_SECONDS = 4 * 60 * 60;
const MAX_DURATION_SECONDS = 12 * 60 * 60;

export interface ElevationRefusal {
  status: number;
  title: string;
  detail?: string;
}

export function isElevationRefusal(value: unknown): value is ElevationRefusal {
  return typeof value === 'object' && value !== null && 'title' in value && 'status' in value;
}

/** In force right now, before anything is granted on the strength of it. */
export function isInForce(assignment: RoleAssignmentRecord, now = new Date()): boolean {
  if (!assignment.ephemeral || !assignment.expiresAt) return false;
  if (assignment.notBefore && Date.parse(assignment.notBefore) > now.getTime()) return false;
  return Date.parse(assignment.expiresAt) > now.getTime();
}

export class ElevationService {
  constructor(private readonly db: Db) {}

  private get assignments() {
    return this.db.collection<RoleAssignmentRecord>(ROLE_ASSIGNMENT_COLLECTION);
  }

  private audit(realm: RealmRecord, input: {
    action: string;
    outcome: 'success' | 'failure';
    subjectId?: string;
    cause?: string;
    detail?: Record<string, unknown>;
    target?: { type: string; ref: string };
  }): void {
    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'privilege',
      ...input,
    });
  }

  /**
   * Requests an elevation.
   *
   * Pending is expressed as an assignment that is not yet in force: `notBefore` sits in the far
   * future until somebody approves it. One record for both states, so an approval cannot lose track
   * of a request and a request cannot grant anything by existing.
   */
  async request(realm: RealmRecord, input: {
    subjectId: string;
    requestedBy: string;
    roleName: string;
    scope?: { kind: string; ref: string };
    justification: string;
    durationSeconds?: number;
    requiresApproval: boolean;
  }): Promise<RoleAssignmentRecord | ElevationRefusal> {
    if (!input.justification?.trim()) {
      // Asked for at the moment of granting because that is the only time anybody actually knows it.
      // An elevation with no stated reason cannot be reviewed later, and "it is in the logs" is not
      // a reason.
      return { status: 400, title: 'A justification is required', detail: 'An elevation with no stated reason cannot be reviewed afterwards.' };
    }

    const role = await this.db.collection<RoleRecord>(ROLE_COLLECTION)
      .findOne({ realmId: realm.realmId, name: input.roleName }, { projection: { _id: 0, roleId: 1 } });
    if (!role) return { status: 404, title: 'No such role' };

    const duration = Math.min(input.durationSeconds ?? DEFAULT_DURATION_SECONDS, MAX_DURATION_SECONDS);
    const now = new Date();
    const assignment: RoleAssignmentRecord = {
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      assignmentId: `elev-${randomUUID()}`,
      subjectId: input.subjectId,
      roleId: role.roleId,
      ...(input.scope ? { scope: input.scope } : {}),
      grantedBy: input.requestedBy,
      grantedAt: now.toISOString(),
      // Ephemeral, so the expiry sweep can never touch a permanent grant.
      ephemeral: true,
      justification: input.justification.trim(),
      ...(input.requiresApproval
        // Awaiting approval, and granting nothing while it waits: a far-future notBefore means every
        // check that honours assignments already ignores it, with no extra state to consult.
        ? { notBefore: new Date(now.getTime() + MAX_DURATION_SECONDS * 1000).toISOString() }
        : {}),
      expiresAt: new Date(now.getTime() + duration * 1000).toISOString(),
      meta: newMeta('RoleAssignment'),
    };
    await this.assignments.insertOne(assignment);

    this.audit(realm, {
      action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
      outcome: 'success',
      subjectId: input.subjectId,
      ...(input.scope ? { target: { type: input.scope.kind, ref: input.scope.ref } } : {}),
      detail: {
        assignmentId: assignment.assignmentId,
        role: input.roleName,
        justification: assignment.justification,
        durationSeconds: duration,
      },
    });
    return assignment;
  }

  async approve(realm: RealmRecord, assignmentId: string, approver: string): Promise<RoleAssignmentRecord | ElevationRefusal> {
    const assignment = await this.assignments.findOne(
      { realmId: realm.realmId, assignmentId, ephemeral: true },
      { projection: { _id: 0 } },
    );
    if (!assignment) return { status: 404, title: 'No such elevation' };
    if (isInForce(assignment)) return { status: 409, title: 'That elevation is already in force' };

    /**
     * The rule that makes approval mean anything at all.
     *
     * Somebody who can approve their own request has not been granted a review; they have been
     * granted the permission permanently, with extra steps and a paper trail that looks like control.
     */
    if (assignment.grantedBy === approver) {
      this.audit(realm, {
        action: 'privilege.approved',
        outcome: 'failure',
        subjectId: approver,
        cause: 'self_approval',
        detail: { assignmentId },
      });
      return { status: 403, title: 'You cannot approve your own elevation' };
    }

    // The clock starts at approval, so time spent waiting for a reviewer is not deducted from the
    // time the work actually gets.
    const now = new Date();
    const duration = Date.parse(assignment.expiresAt as string) - Date.parse(assignment.grantedAt);
    await this.assignments.updateOne(
      { assignmentId },
      {
        $set: {
          approvalRef: approver,
          expiresAt: new Date(now.getTime() + duration).toISOString(),
          'meta.lastModified': now.toISOString(),
        },
        $unset: { notBefore: '' },
      },
    );

    this.audit(realm, {
      action: 'privilege.approved',
      outcome: 'success',
      subjectId: assignment.subjectId,
      detail: { assignmentId, approvedBy: approver },
    });
    return { ...assignment, approvalRef: approver, notBefore: undefined };
  }

  /**
   * Everything currently elevated in the realm.
   *
   * The question the design this replaces could not answer at all, and an ordinary one during an
   * incident.
   */
  async listInForce(realmId: string): Promise<RoleAssignmentRecord[]> {
    const held = await this.assignments
      .find({ realmId, ephemeral: true }, { projection: { _id: 0 } })
      .sort({ grantedAt: -1 })
      .toArray();
    return held.filter((assignment) => isInForce(assignment));
  }

  /** Everything awaiting a reviewer, so a request cannot sit unnoticed until it expires. */
  async listPending(realmId: string): Promise<RoleAssignmentRecord[]> {
    const held = await this.assignments
      .find({ realmId, ephemeral: true, notBefore: { $exists: true } }, { projection: { _id: 0 } })
      .sort({ grantedAt: -1 })
      .toArray();
    return held.filter((assignment) => !isInForce(assignment) && Date.parse(assignment.expiresAt as string) > Date.now());
  }

  /**
   * Ends an elevation before its expiry.
   *
   * The other thing the previous design could not do: a capability granted in error used to run to
   * its expiry regardless of what anybody decided afterwards. Deleted rather than marked, because an
   * assignment that lingers is one the decision point might still honour, and the security event is
   * where the history lives.
   */
  async revoke(realm: RealmRecord, assignmentId: string, revokedBy: string, reason: string): Promise<boolean> {
    const result = await this.assignments.deleteOne({ realmId: realm.realmId, assignmentId, ephemeral: true });
    if (result.deletedCount === 0) return false;

    this.audit(realm, {
      action: 'privilege.revoked',
      outcome: 'success',
      subjectId: revokedBy,
      detail: { assignmentId, reason },
    });
    return true;
  }
}
