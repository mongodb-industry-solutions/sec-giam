import { Db } from 'mongodb';
import { PRINCIPAL_COLLECTION, ROLE_COLLECTION } from '../../../shared/models/collections';
import { RoleRecord } from '../../authorization/models/authorization.model';
import {
  PrincipalRecord, RoleHolding, MAX_ROLE_HOLDINGS,
} from '../../directory/models/principal.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { SecurityEventService } from '../../audit/services/securityEvent.service';

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

/**
 * An elevation, with the subject that holds it.
 *
 * A holding embedded in a principal has no identifier of its own, so an elevation is addressed by
 * the pair `(subjectId, roleId)`. That pair is already unique: a subject either holds a role or
 * does not.
 */
export interface ElevationView extends RoleHolding {
  subjectId: string;
  /**
   * The name behind the subject. An elevation screen reads "held by" and then an identifier, which
   * names nobody a reviewer can recognise. Free here: the principal is already being read.
   */
  userName?: string;
}

/** In force right now, before anything is granted on the strength of it. */
export function isInForce(holding: RoleHolding, now = new Date()): boolean {
  if (!holding.ephemeral || !holding.expiresAt) return false;
  if (holding.pendingApproval) return false;
  return Date.parse(holding.expiresAt) > now.getTime();
}

/**
 * Past its expiry: an elevation that has already been spent, whether or not it was ever approved.
 *
 * Distinct from `isInForce` being false, which is also true of one still awaiting a reviewer. A
 * pending request is alive and must be left alone; a spent one grants nothing and never will again.
 */
export function isSpent(holding: RoleHolding, now = new Date()): boolean {
  if (!holding.ephemeral || !holding.expiresAt) return false;
  return Date.parse(holding.expiresAt) <= now.getTime();
}

export class ElevationService {
  constructor(private readonly db: Db) {}

  private get principals() {
    return this.db.collection<PrincipalRecord>(PRINCIPAL_COLLECTION);
  }

  /** Every ephemeral holding in the realm, with the subject each belongs to. */
  private async ephemeralHoldings(realmId: string): Promise<ElevationView[]> {
    const holders = await this.principals
      .find({ realmId, 'roles.ephemeral': true }, { projection: { _id: 0, subjectId: 1, userName: 1, roles: 1 } })
      .toArray();
    const found: ElevationView[] = [];
    for (const holder of holders) {
      for (const holding of holder.roles ?? []) {
        if (holding.ephemeral) {
          found.push({
            ...holding,
            subjectId: holder.subjectId,
            ...(holder.userName ? { userName: holder.userName } : {}),
          });
        }
      }
    }
    return found.sort((a, b) => b.grantedAt.localeCompare(a.grantedAt));
  }

  /** One ephemeral holding, addressed by the pair. */
  private async ephemeralHolding(
    realmId: string,
    subjectId: string,
    roleId: string,
  ): Promise<ElevationView | null> {
    const principal = await this.principals.findOne(
      { realmId, subjectId },
      { projection: { _id: 0, userName: 1, roles: 1 } },
    );
    const holding = (principal?.roles ?? []).find((entry) => entry.roleId === roleId && entry.ephemeral);
    return holding
      ? { ...holding, subjectId, ...(principal?.userName ? { userName: principal.userName } : {}) }
      : null;
  }

  private audit(realm: RealmRecord, input: {
    action: string;
    outcome: 'success' | 'failure';
    subjectId?: string;
    cause?: string;
    detail?: Record<string, unknown>;
    target?: { type: string; ref: string };
    stakeholderSubjectIds?: string[];
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
   * Pending is an explicit `pendingApproval` flag that every activity check fails closed on. It
   * replaces dating `notBefore` far in the future so the expiry checks would skip the entry: that
   * worked, and it meant a live-looking assignment granted nothing for reasons a reader had to know
   * the convention to see. One entry covers both states, so an approval cannot lose track of a
   * request and a request cannot grant anything merely by existing.
   */
  async request(realm: RealmRecord, input: {
    subjectId: string;
    requestedBy: string;
    roleName: string;
    scope?: { kind: string; ref: string };
    justification: string;
    durationSeconds?: number;
    requiresApproval: boolean;
  }): Promise<ElevationView | ElevationRefusal> {
    if (!input.justification?.trim()) {
      this.audit(realm, {
        action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
        outcome: 'failure',
        subjectId: input.requestedBy,
        cause: 'no_justification',
        detail: { role: input.roleName, holder: input.subjectId },
      });
      // Asked for at the moment of granting because that is the only time anybody actually knows it.
      // An elevation with no stated reason cannot be reviewed later, and "it is in the logs" is not
      // a reason.
      return { status: 400, title: 'A justification is required', detail: 'An elevation with no stated reason cannot be reviewed afterwards.' };
    }

    const role = await this.db.collection<RoleRecord>(ROLE_COLLECTION)
      .findOne({ realmId: realm.realmId, name: input.roleName }, { projection: { _id: 0, roleId: 1 } });
    if (!role) {
      // Naming a role that does not exist is how somebody finds out which ones do, so the attempt is
      // recorded even though nothing was granted.
      this.audit(realm, {
        action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
        outcome: 'failure',
        subjectId: input.requestedBy,
        cause: 'unknown_role',
        detail: { role: input.roleName, holder: input.subjectId },
      });
      return { status: 404, title: 'No such role' };
    }

    const duration = Math.min(input.durationSeconds ?? DEFAULT_DURATION_SECONDS, MAX_DURATION_SECONDS);
    const now = new Date();
    const holding: RoleHolding = {
      roleId: role.roleId,
      ...(input.scope ? { scope: input.scope } : {}),
      grantedBy: input.requestedBy,
      grantedAt: now.toISOString(),
      // Ephemeral, so the expiry sweep can never touch a permanent grant.
      ephemeral: true,
      justification: input.justification.trim(),
      ...(input.requiresApproval ? { pendingApproval: true } : {}),
      expiresAt: new Date(now.getTime() + duration * 1000).toISOString(),
    };

    // A duplicate is the SAME role for the SAME scope, not merely the same role name. A subject who
    // already holds a role bank-wide (or for a different case) can still ask for it again scoped to
    // THIS case: that is a distinct, reviewable, time-boxed grant, not a repeat of the standing one.
    // Comparing roleId alone would refuse the request that matters most: the standing L2 investigator
    // approving their own case-scoped access, which is exactly the elevation this endpoint exists for.
    const principal = await this.principals.findOne(
      { realmId: realm.realmId, subjectId: input.subjectId },
      { projection: { _id: 0, userName: 1, roles: 1 } },
    );
    const existingHoldings = principal?.roles ?? [];
    const sameScope = (a?: { kind: string; ref: string }, b?: { kind: string; ref: string }) => {
      if (!a && !b) return true;
      if (!a || !b) return false;
      return a.kind === b.kind && a.ref === b.ref;
    };
    const existing = existingHoldings.find(
      (entry) => entry.roleId === role.roleId && sameScope(entry.scope, input.scope),
    );

    // An EXPIRED holding is not a duplicate of this request, it is the remains of an earlier one.
    // Treating it as a duplicate made the expiry permanent in the wrong direction: the re-derivation
    // branch below handed the dead entry back as a success, the resource server believed the access
    // had been granted, and every check against it answered "not in force". The scope could then
    // never be elevated again, because the spent entry went on matching. It is removed here, and the
    // request proceeds as the genuinely new grant it is, with its own clock and its own audit event.
    const duplicate = existing && !isSpent(existing) ? existing : undefined;
    // What the principal holds once a spent entry is gone: the cap below counts this, not the
    // holdings as read, or removing the spent entry would free a slot the check never sees.
    let holdingsAfter = existingHoldings;
    if (existing && !duplicate) {
      // Matched on scope too, so only THIS spent entry goes: the same role held for another scope
      // with the same expiry is unrelated authority and must survive.
      await this.principals.updateOne(
        { realmId: realm.realmId, subjectId: input.subjectId },
        {
          $pull: {
            roles: {
              roleId: role.roleId,
              ephemeral: true,
              expiresAt: existing.expiresAt,
              scope: existing.scope ?? { $exists: false },
            },
          },
        } as never,
      );
      holdingsAfter = existingHoldings.filter((entry) => entry !== existing);
    }

    if (duplicate) {
      // A repeat of the SAME request, by the SAME subject, for the SAME role and scope, grants no
      // authority the subject does not already hold, so answering it is a re-derivation rather than
      // a second elevation. Refusing it here is what made the accepting L2's own page reload, or a
      // second tab, unable to recover the token it already holds: every call after the first read as
      // an attempt to elevate twice and was refused, even though nothing new was being asked for.
      // Only requested BY the holder themselves: somebody else asking for a subject's already-held
      // scope is a different question (why are you asking for what they have), and stays refused.
      if (input.requestedBy === input.subjectId) {
        return { ...duplicate, subjectId: input.subjectId };
      }
      this.audit(realm, {
        action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
        outcome: 'failure',
        subjectId: input.requestedBy,
        cause: 'already_held_for_scope',
        detail: { role: input.roleName, holder: input.subjectId },
      });
      return {
        status: 409,
        title: 'That principal already holds this role for this scope',
        detail: 'An elevation adds authority the subject does not already have for this scope.',
      };
    }
    if (holdingsAfter.length >= MAX_ROLE_HOLDINGS) {
      this.audit(realm, {
        action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
        outcome: 'failure',
        subjectId: input.requestedBy,
        cause: 'role_cap_reached',
        detail: { role: input.roleName, holder: input.subjectId },
      });
      return {
        status: 409,
        title: 'Role holding cap reached',
        detail: 'This principal already holds the maximum number of role assignments.',
      };
    }

    const outcome = await this.principals.updateOne(
      { realmId: realm.realmId, subjectId: input.subjectId },
      { $push: { roles: holding } },
    );
    if (outcome.matchedCount === 0) {
      this.audit(realm, {
        action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
        outcome: 'failure',
        subjectId: input.requestedBy,
        cause: 'already_held_or_at_cap',
        detail: { role: input.roleName, holder: input.subjectId },
      });
      return {
        status: 409,
        title: 'That principal already holds this role',
        detail: 'An elevation adds authority the subject does not already have, or the role cap is reached.',
      };
    }

    this.audit(realm, {
      action: input.requiresApproval ? 'privilege.requested' : 'privilege.granted',
      outcome: 'success',
      subjectId: input.subjectId,
      ...(input.scope ? { target: { type: input.scope.kind, ref: input.scope.ref } } : {}),
      detail: {
        holder: input.subjectId,
        roleId: role.roleId,
        role: input.roleName,
        justification: holding.justification,
        durationSeconds: duration,
      },
    });
    return { ...holding, subjectId: input.subjectId };
  }

  async approve(
    realm: RealmRecord,
    subjectId: string,
    roleId: string,
    approver: string,
  ): Promise<ElevationView | ElevationRefusal> {
    const holding = await this.ephemeralHolding(realm.realmId, subjectId, roleId);
    if (!holding) {
      this.audit(realm, {
        action: 'privilege.approved',
        outcome: 'failure',
        subjectId: approver,
        cause: 'no_such_elevation',
        detail: { holder: subjectId, roleId },
      });
      return { status: 404, title: 'No such elevation' };
    }
    if (isInForce(holding)) {
      this.audit(realm, {
        action: 'privilege.approved',
        outcome: 'failure',
        subjectId: approver,
        cause: 'already_in_force',
        detail: { holder: subjectId, roleId },
      });
      return { status: 409, title: 'That elevation is already in force' };
    }

    /**
     * The rule that makes approval mean anything at all.
     *
     * Somebody who can approve their own request has not been granted a review; they have been
     * granted the permission permanently, with extra steps and a paper trail that looks like control.
     */
    if (holding.grantedBy === approver) {
      this.audit(realm, {
        action: 'privilege.approved',
        outcome: 'failure',
        subjectId: approver,
        cause: 'self_approval',
        detail: { holder: subjectId, roleId },
      });
      return { status: 403, title: 'You cannot approve your own elevation' };
    }

    // The clock starts at approval, so time spent waiting for a reviewer is not deducted from the
    // time the work actually gets.
    const now = new Date();
    const duration = Date.parse(holding.expiresAt as string) - Date.parse(holding.grantedAt);
    const expiresAt = new Date(now.getTime() + duration).toISOString();

    // Positional, so the update reaches THIS holding and never another entry in the same array.
    await this.principals.updateOne(
      { realmId: realm.realmId, subjectId, 'roles.roleId': roleId },
      {
        $set: {
          'roles.$.approvalRef': approver,
          'roles.$.expiresAt': expiresAt,
          'meta.lastModified': now.toISOString(),
        },
        $unset: { 'roles.$.pendingApproval': '' },
      },
    );

    this.audit(realm, {
      action: 'privilege.approved',
      outcome: 'success',
      subjectId,
      // The person who asked for it. Their request became authority the moment somebody approved it,
      // and it is the only event that says so.
      ...(holding.grantedBy ? { stakeholderSubjectIds: [holding.grantedBy] } : {}),
      detail: { holder: subjectId, roleId, approvedBy: approver },
    });
    return {
      ...holding, approvalRef: approver, expiresAt, pendingApproval: undefined,
    };
  }

  /**
   * Everything currently elevated in the realm.
   *
   * The question the design this replaces could not answer at all, and an ordinary one during an
   * incident.
   */
  async listInForce(realmId: string): Promise<ElevationView[]> {
    const held = await this.ephemeralHoldings(realmId);
    return held.filter((holding) => isInForce(holding));
  }

  /**
   * Whether the SUBJECT ASKING holds their own in-force elevation for a scope, right now.
   *
   * `listInForce` answers "who holds elevated access", which is an oversight question and is
   * permissioned as one: a role has to be granted `elevations:view` to ask it. Proving you hold your
   * own grant is a different, narrower question a role does not need that permission to ask, the
   * same way reading your own profile needs no special grant. Without this, the only way a resource
   * server had to check a caller's elevation was the oversight list, which the caller holding the
   * elevation was itself never permissioned to call, so the elevation, once granted, could not
   * actually be exercised.
   */
  async holdsInForce(realmId: string, subjectId: string, scope: { kind: string; ref: string }): Promise<boolean> {
    const principal = await this.principals.findOne(
      { realmId, subjectId },
      { projection: { _id: 0, roles: 1 } },
    );
    return (principal?.roles ?? []).some(
      (holding) => holding.scope?.kind === scope.kind && holding.scope?.ref === scope.ref && isInForce(holding),
    );
  }

  /** Everything awaiting a reviewer, so a request cannot sit unnoticed until it expires. */
  async listPending(realmId: string): Promise<ElevationView[]> {
    const held = await this.ephemeralHoldings(realmId);
    return held.filter(
      (holding) => holding.pendingApproval && Date.parse(holding.expiresAt as string) > Date.now(),
    );
  }

  /**
   * Ends an elevation before its expiry.
   *
   * The other thing the previous design could not do: a capability granted in error used to run to
   * its expiry regardless of what anybody decided afterwards. Pulled from the array rather than
   * marked, because a holding that lingers is one the decision point might still honour, and the
   * security event is where the history lives.
   */
  async revoke(
    realm: RealmRecord,
    subjectId: string,
    roleId: string,
    revokedBy: string,
    reason: string,
  ): Promise<boolean> {
    const result = await this.principals.updateOne(
      { realmId: realm.realmId, subjectId, 'roles.roleId': roleId, 'roles.ephemeral': true },
      { $pull: { roles: { roleId, ephemeral: true } } },
    );
    if (result.modifiedCount === 0) {
      this.audit(realm, {
        action: 'privilege.revoked',
        outcome: 'failure',
        subjectId: revokedBy,
        cause: 'no_such_elevation',
        detail: { holder: subjectId, roleId, reason },
      });
      return false;
    }

    this.audit(realm, {
      action: 'privilege.revoked',
      outcome: 'success',
      subjectId: revokedBy,
      detail: { holder: subjectId, roleId, reason },
    });
    return true;
  }
}
