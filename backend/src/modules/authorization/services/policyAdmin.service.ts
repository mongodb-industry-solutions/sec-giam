import { Db } from 'mongodb';
import RE2 from 're2';
import { recordConfigurationChange } from '../../audit/services/configurationChange';
import { v4 as uuidv4 } from 'uuid';
import { POLICY_COLLECTION } from '../../../shared/models/collections';
import { newMeta, touchMeta } from '../../../shared/models/base.model';
import {
  PolicyRecord, PolicyCondition, POLICY_CONDITION_KEYS, PolicyConditionKey, Selector,
  isInEffect, selectorApplies,
} from '../models/policy.model';
import { parsePermission } from '../models/resource.model';
import { RoleAdminService } from './roleAdmin.service';

/**
 * Administering the conditional statements evaluated after roles.
 *
 * The decision point answers "may this principal do this, right now". This answers the two questions
 * an administrator asks instead: what does the realm state, and what would change if I edited it.
 * Both read the same collection the evaluator reads, so there is no second source of truth.
 *
 * The condition language is CLOSED, and closing it is the point rather than a limitation. An open
 * expression here would let a policy encode a business rule, and the boundary between identity
 * context and business materiality is exactly what must not blur: a threshold belongs to the system
 * that can observe the inputs, and an authority that cannot see them would be guessing.
 */

export type PolicyRefusal = { status: number; title: string; detail: string };

export function isPolicyRefusal(value: unknown): value is PolicyRefusal {
  return typeof value === 'object' && value !== null && 'status' in value && 'title' in value;
}

export interface PolicySummary {
  policyId: string;
  name: string;
  version: number;
  status: PolicyRecord['status'];
  /** Named outright, because "does this policy prohibit anything" is the first question asked. */
  effect: 'allow' | 'deny';
  /** What it governs. Carried on the summary, not only the detail, so a resource's own screen can
   * ask "which policies govern me" without a round trip per policy to find out. */
  resource: Selector;
  /** `resolvedPermissions.length`: what this policy concretely covers right now, roles expanded. */
  permissionCount: number;
  conditionCount: number;
  /** False while a policy is drafted or dated ahead, so a list shows what actually decides today. */
  inEffect: boolean;
  created?: string;
  lastModified?: string;
}

export interface PolicyDetail extends PolicySummary {
  /** What an author added directly, `resource:action`. Never mutated by a role reference. */
  permission: Selector;
  /** Roles whose current, expanded grants are folded into `resolvedPermissions`. Provenance only. */
  role?: Selector;
  principal?: Selector;
  /** The actual, flat set this policy is evaluated against. See `PolicyRecord.resolvedPermissions`. */
  resolvedPermissions: string[];
  conditions: PolicyCondition[];
  obligations?: PolicyRecord['obligations'];
  approvedBy?: string;
  effectiveFrom?: string;
  reason?: string;
}

const ASSURANCE_LEVELS = ['aal1', 'aal2', 'aal3'];

/**
 * Refuses anything the evaluator would not understand, before it is stored.
 *
 * Static checks only: shape, spelling, and whether every pattern present compiles under RE2. Static,
 * because it has no database to check a named role against — that half of validation (does `role`
 * name a real role, does the whole thing resolve to at least one permission) needs a read and lives
 * in `resolvePermissions` below, run by every write path right after this.
 *
 * Checked here as well as in the request schema on purpose. The schema protects the HTTP surface; a
 * seeder and any future caller reach the collection through this class, and a rule enforced in only
 * one of the two is a rule with a way around it.
 */
export function validatePolicy(policy: {
  effect?: 'allow' | 'deny';
  permission?: Selector;
  resource?: Selector;
  principal?: Selector;
  role?: Selector;
  conditions?: PolicyCondition[];
}): PolicyRefusal | null {
  if (policy.effect !== 'allow' && policy.effect !== 'deny') {
    return {
      status: 400,
      title: 'Unknown effect',
      detail: `A policy names effect "${policy.effect}". Only allow and deny exist.`,
    };
  }

  const resource = policy.resource ?? {};
  if (!resource.ids?.length && !resource.pattern) {
    return {
      status: 400,
      title: 'Policy names no resource',
      detail: 'A policy states what it governs: named resources, or a pattern. Neither was given.',
    };
  }
  if (resource.ids?.some((id) => !id)) {
    return { status: 400, title: 'Empty resource id', detail: 'A resource id cannot be empty.' };
  }

  for (const permission of policy.permission?.ids ?? []) {
    // A permission is `resource:action` everywhere it appears, so a policy naming something that is
    // not one would never match a request, however the request was spelled.
    if (!parsePermission(permission)) {
      return {
        status: 400,
        title: 'Not a permission',
        detail:
          `"${permission}" is not of the form resource:action. That is the one spelling a role, a `
          + 'policy and a token all use, so a policy written another way matches nothing.',
      };
    }
  }

  if (policy.role?.ids?.some((id) => !id)) {
    return { status: 400, title: 'Empty role name', detail: 'A role name cannot be empty.' };
  }

  for (const [label, selector] of [
    ['resource', policy.resource], ['permission', policy.permission],
    ['principal', policy.principal], ['role', policy.role],
  ] as const) {
    if (selector?.pattern) {
      try {
        // eslint-disable-next-line no-new
        new RE2(selector.pattern);
      } catch {
        return {
          status: 400,
          title: 'Not a valid pattern',
          detail:
            `"${selector.pattern}" (in ${label}) does not compile as a regular expression under RE2. `
            + 'RE2 is used deliberately rather than the language\'s own engine, because RE2 guarantees '
            + 'linear-time matching and a small number of Perl constructs (lookaheads among them) it '
            + 'refuses to compile are exactly the ones that make that guarantee possible.',
        };
      }
    }
  }

  const allowed = new Set<string>(POLICY_CONDITION_KEYS);

  for (const [index, condition] of (policy.conditions ?? []).entries()) {
    const at = `Condition ${index + 1}`;

    const unknown = Object.keys(condition).filter((key) => !allowed.has(key));
    if (unknown.length > 0) {
      return {
        status: 400,
        title: 'Condition outside the vocabulary',
        detail:
          `${at} names ${unknown.join(', ')}, which this authority cannot evaluate. Conditions are `
          + `identity context only (${[...allowed].join(', ')}). A condition expressing a business `
          + 'threshold belongs to the system that can observe the inputs, not to an identity authority.',
      };
    }

    if (condition.assuranceAtLeast !== undefined && !ASSURANCE_LEVELS.includes(condition.assuranceAtLeast)) {
      return { status: 400, title: 'Unknown assurance level', detail: `${at} names assurance "${condition.assuranceAtLeast}".` };
    }
    if (condition.ipInRange !== undefined && (!Array.isArray(condition.ipInRange) || condition.ipInRange.length === 0)) {
      return { status: 400, title: 'Empty address range', detail: `${at} carries an address condition that matches nothing.` };
    }
    if (condition.timeOfDayUtc !== undefined) {
      const { from, to } = condition.timeOfDayUtc;
      const whole = (hour: unknown) => Number.isInteger(hour) && (hour as number) >= 0 && (hour as number) <= 23;
      if (!whole(from) || !whole(to)) {
        return { status: 400, title: 'Hour out of range', detail: `${at} names hours outside 0 to 23. The window is UTC and half open.` };
      }
    }
    if (condition.tenantIs !== undefined && !condition.tenantIs) {
      return { status: 400, title: 'Empty tenant', detail: `${at} carries a tenant condition with no tenant.` };
    }
    if (condition.heldRole !== undefined && (!Array.isArray(condition.heldRole) || condition.heldRole.length === 0)) {
      return { status: 400, title: 'Empty role requirement', detail: `${at} carries a role condition that matches nothing.` };
    }
    if (condition.heldPermission !== undefined
      && (!Array.isArray(condition.heldPermission) || condition.heldPermission.length === 0)) {
      return { status: 400, title: 'Empty permission requirement', detail: `${at} carries a permission condition that matches nothing.` };
    }
    for (const permission of condition.heldPermission ?? []) {
      // Same one spelling everywhere. A condition naming something that is not resource:action would
      // never hold, however it was meant.
      if (!parsePermission(permission)) {
        return {
          status: 400,
          title: 'Not a permission',
          detail: `${at} names "${permission}" as a required permission, which is not of the form resource:action.`,
        };
      }
    }
  }
  return null;
}

/**
 * The one place `permission` and `role` are turned into `resolvedPermissions`.
 *
 * Every write path (`PolicyAdminService.create`/`update`, the seeder, and the role-triggered
 * resync below) goes through this, so there is exactly one idea of what a policy naming a role
 * actually resolves to. Needs the database (to expand a named role through its parents), which is
 * why this is not part of the purely static `validatePolicy` above.
 */
export async function resolvePermissions(
  db: Db,
  realmId: string,
  input: { permission?: Selector; role?: Selector },
): Promise<{ resolvedPermissions: string[] } | PolicyRefusal> {
  const fromRoles = await new RoleAdminService(db).effectivePermissionsFor(realmId, input.role);
  if (fromRoles.unknownIds.length > 0) {
    return {
      status: 400,
      title: 'Unknown role',
      detail: `No role in this realm is named ${fromRoles.unknownIds.join(', ')}.`,
    };
  }

  const explicit = input.permission?.ids ?? [];
  const resolvedPermissions = [...new Set([...explicit, ...fromRoles.permissions])].sort();

  // A `permission.pattern` (ids absent) still governs something even though nothing was pre-expanded
  // for it: it is checked live, at decision time, exactly like `resource.pattern` already is.
  const hasPatternReach = Boolean(input.permission?.pattern) && !input.permission?.ids?.length;
  if (resolvedPermissions.length === 0 && !hasPatternReach) {
    return {
      status: 400,
      title: 'Policy governs nothing',
      detail:
        'A policy with no permission decides nothing and would sit in the list looking as though it '
        + 'did. Name at least one permission, a role that grants one, or a pattern.',
    };
  }
  return { resolvedPermissions };
}

export class PolicyAdminService {
  constructor(private readonly db: Db) {}

  private get policies() {
    return this.db.collection<PolicyRecord>(POLICY_COLLECTION);
  }

  private static summary(policy: PolicyRecord): PolicySummary {
    return {
      policyId: policy.policyId,
      name: policy.name,
      version: policy.version,
      status: policy.status,
      effect: policy.effect,
      resource: policy.resource,
      permissionCount: (policy.resolvedPermissions ?? []).length,
      conditionCount: (policy.conditions ?? []).length,
      inEffect: isInEffect(policy),
      ...(policy.meta?.created ? { created: policy.meta.created } : {}),
      ...(policy.meta?.lastModified ? { lastModified: policy.meta.lastModified } : {}),
    };
  }

  async list(
    realmId: string,
    options: {
      q?: string; status?: PolicyRecord['status']; governs?: string; skip?: number; limit?: number;
    } = {},
  ): Promise<{ policies: PolicySummary[]; total: number }> {
    const skip = Math.max(0, options.skip ?? 0);
    const limit = Math.min(200, Math.max(1, options.limit ?? 20));
    // Every independent condition collected as its own clause and combined with `$and`, rather than
    // each one assigning its own `$or` onto one shared object: two clauses that both happen to need
    // `$or` (the name/version search, and the `governs` candidate filter below) would otherwise have
    // the second silently overwrite the first, and a search box that quietly stopped narrowing
    // anything is worse than one that was never offered.
    const clauses: Record<string, unknown>[] = [{ realmId }];
    if (options.status) clauses.push({ status: options.status });
    if (options.q) {
      // Anchored on the two fields a person would search by. Escaped, because a search box is not a
      // place to accept an expression the database will then run.
      const escaped = options.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      clauses.push({ $or: [{ name: { $regex: escaped, $options: 'i' } }, { version: { $regex: escaped, $options: 'i' } }] });
    }

    if (options.governs) {
      // Every candidate that could possibly govern this resource: an exact id is a plain equality
      // a query can decide, but `resource.pattern` is a regular expression a query cannot evaluate,
      // so a policy using one is a candidate here and `selectorApplies` decides for real below. This
      // is a screen a human reads, not the decision path, so filtering candidates in memory rather
      // than pushing every last bit of it into the query is the right trade here.
      clauses.push({ $or: [{ 'resource.ids': options.governs }, { 'resource.pattern': { $exists: true } }] });
      const candidates = await this.policies
        .find({ $and: clauses }, { projection: { _id: 0 } })
        .sort({ name: 1 })
        .toArray();
      const matching = candidates.filter((policy) => selectorApplies(policy.resource, options.governs!));
      return {
        policies: matching.slice(skip, skip + limit).map((policy) => PolicyAdminService.summary(policy)),
        total: matching.length,
      };
    }

    const filter = { $and: clauses };
    const [found, total] = await Promise.all([
      this.policies.find(filter, { projection: { _id: 0 } }).sort({ name: 1 }).skip(skip).limit(limit).toArray(),
      this.policies.countDocuments(filter),
    ]);
    return { policies: found.map((policy) => PolicyAdminService.summary(policy)), total };
  }

  async detail(realmId: string, policyId: string): Promise<PolicyDetail | null> {
    const policy = await this.policies.findOne({ realmId, policyId }, { projection: { _id: 0 } });
    if (!policy) return null;
    return {
      ...PolicyAdminService.summary(policy),
      permission: policy.permission ?? {},
      resolvedPermissions: policy.resolvedPermissions ?? [],
      conditions: policy.conditions ?? [],
      ...(policy.role ? { role: policy.role } : {}),
      ...(policy.principal ? { principal: policy.principal } : {}),
      ...(policy.obligations ? { obligations: policy.obligations } : {}),
      ...(policy.approvedBy ? { approvedBy: policy.approvedBy } : {}),
      ...(policy.effectiveFrom ? { effectiveFrom: policy.effectiveFrom } : {}),
      ...(policy.reason ? { reason: policy.reason } : {}),
    };
  }

  async create(
    realmId: string,
    tenantId: string,
    input: {
      name: string; version?: number; status?: PolicyRecord['status'];
      effect: 'allow' | 'deny'; resource: Selector; permission?: Selector;
      role?: Selector; principal?: Selector; conditions?: PolicyCondition[];
      obligations?: PolicyRecord['obligations']; approvedBy?: string; effectiveFrom?: string;
      reason?: string;
    },
  ): Promise<PolicyDetail | PolicyRefusal> {
    const clash = await this.policies.findOne({ realmId, name: input.name }, { projection: { _id: 0, policyId: 1 } });
    if (clash) {
      return {
        status: 409,
        title: 'Policy already exists',
        detail:
          `This realm already has a policy named "${input.name}". Names identify the deciding policy `
          + 'in a decision record, so two of them would make that record ambiguous.',
      };
    }

    const invalid = validatePolicy(input);
    if (invalid) return invalid;

    const resolved = await resolvePermissions(this.db, realmId, input);
    if (isPolicyRefusal(resolved)) return resolved;

    const policyId = uuidv4();
    await this.policies.insertOne({
      realmId,
      tenantId,
      policyId,
      name: input.name,
      version: input.version ?? 1,
      // Defaulting to draft is tempting and would be wrong: the previous shape defaulted to
      // enabled, and quietly changing that would leave a deployment's policies inert with nothing
      // to say so.
      status: input.status ?? 'active',
      effect: input.effect,
      resource: input.resource,
      permission: input.permission ?? {},
      resolvedPermissions: resolved.resolvedPermissions,
      conditions: input.conditions ?? [],
      ...(input.role ? { role: input.role } : {}),
      ...(input.principal ? { principal: input.principal } : {}),
      ...(input.obligations?.length ? { obligations: input.obligations } : {}),
      ...(input.approvedBy ? { approvedBy: input.approvedBy } : {}),
      ...(input.effectiveFrom ? { effectiveFrom: input.effectiveFrom } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      meta: newMeta('Policy'),
    });
    return await this.detail(realmId, policyId) as PolicyDetail;
  }

  /**
   * Partial, and every list is replaced rather than merged.
   *
   * A policy is a statement of what it says, so merging would make removing a permission or a
   * condition impossible from here, and a deny nobody can delete is worse than one nobody can add.
   *
   * `resolvedPermissions` is recomputed unconditionally, whether or not this particular patch touched
   * `permission` or `role`: recomputing is one cheap role read and guarantees the field can never
   * drift from what `permission`/`role` actually say, rather than only being refreshed when the
   * caller remembered to ask.
   */
  async update(
    realmId: string,
    policyId: string,
    /** Who is changing it. Never inferred: a change nobody can attribute is one that should not be possible. */
    actorSubjectId: string,
    tenantId: string,
    patch: {
      version?: number; status?: PolicyRecord['status']; effect?: 'allow' | 'deny';
      resource?: Selector; permission?: Selector; role?: Selector; principal?: Selector;
      conditions?: PolicyCondition[]; obligations?: PolicyRecord['obligations'];
      approvedBy?: string; effectiveFrom?: string; reason?: string;
    },
  ): Promise<PolicyDetail | PolicyRefusal | null> {
    const policy = await this.policies.findOne({ realmId, policyId }, { projection: { _id: 0 } });
    if (!policy) return null;

    const changes: Partial<PolicyRecord> = {};
    for (const field of [
      'version', 'status', 'effect', 'resource', 'permission', 'role', 'principal',
      'obligations', 'approvedBy', 'effectiveFrom', 'reason', 'conditions',
    ] as const) {
      if (patch[field] !== undefined) (changes as Record<string, unknown>)[field] = patch[field];
    }

    // Validated (and resolved) against the MERGED policy, so a patch cannot slip a condition, or an
    // unresolved role reference, past the check by sending it without the fields the check reads
    // beside it.
    const merged = { ...policy, ...changes };
    const invalid = validatePolicy(merged);
    if (invalid) return invalid;

    const resolved = await resolvePermissions(this.db, realmId, merged);
    if (isPolicyRefusal(resolved)) return resolved;
    changes.resolvedPermissions = resolved.resolvedPermissions;

    if (Object.keys(changes).length > 0) {
      await this.policies.updateOne({ realmId, policyId }, { $set: { ...changes, meta: touchMeta(policy.meta) } });
    }

    /**
     * Recorded with the value BEFORE and after, which `meta.version` cannot express.
     *
     * A policy decides who may do what, so "who changed this from allow to deny, and when" is the
     * question an investigation asks first. It was unanswerable: the version counter moved and
     * nothing recorded which attribute did.
     */
    await recordConfigurationChange(this.db, {
      realmId,
      tenantId,
      what: 'policy',
      ref: policyId,
      operation: 'updated',
      actorSubjectId,
      before: policy as unknown as Record<string, unknown>,
      after: { ...policy, ...changes } as unknown as Record<string, unknown>,
    });

    return await this.detail(realmId, policyId);
  }

  /**
   * Removes a policy outright.
   *
   * Unlike a role, nothing else in the model references a policy, so there is no dependant to
   * orphan. Disabling it is the reversible option and the console offers both, because withdrawing
   * a prohibition is a decision worth being able to undo.
   */
  async remove(realmId: string, policyId: string): Promise<{ removed: true } | null> {
    const outcome = await this.policies.deleteOne({ realmId, policyId });
    return outcome.deletedCount === 0 ? null : { removed: true };
  }

  /**
   * Called after a role's permissions or composition change (`role.controller.ts`, right after
   * `RoleAdminService.update`), with the FULL set of role names that change touched
   * (`RoleAdminService.namesAffectedByChangeTo`, which already walks inheritance so a parent's
   * change reaches a policy naming only a descendant).
   *
   * Every policy naming any of these roles gets `resolvedPermissions` recomputed from what its
   * roles currently grant, re-saved with a bumped version if anything actually changed. A policy
   * whose `role` now names something that no longer exists is left alone rather than silently
   * dropped: that is a data problem worth surfacing on the policy's own screen, not something a
   * background sweep should paper over.
   */
  async resyncRoleReferences(realmId: string, roleNames: string[]): Promise<number> {
    if (roleNames.length === 0) return 0;

    const [byIds, byPattern] = await Promise.all([
      this.policies.find({ realmId, 'role.ids': { $in: roleNames } }, { projection: { _id: 0 } }).toArray(),
      // A `role.pattern` candidate cannot be excluded by the query above (it names no id directly),
      // so every policy using one is a candidate here, resolved for real just below.
      this.policies.find({ realmId, 'role.pattern': { $exists: true } }, { projection: { _id: 0 } }).toArray(),
    ]);
    const byPolicyId = new Map([...byIds, ...byPattern].map((policy) => [policy.policyId, policy]));

    let resynced = 0;
    for (const policy of byPolicyId.values()) {
      const resolved = await resolvePermissions(this.db, realmId, policy);
      // A role reference that no longer resolves is left as-is here; it surfaces on the policy's own
      // screen instead, the same way an unenforced permission does on a role's.
      if (isPolicyRefusal(resolved)) continue;
      if (JSON.stringify(resolved.resolvedPermissions) === JSON.stringify(policy.resolvedPermissions ?? [])) continue;
      await this.policies.updateOne(
        { realmId, policyId: policy.policyId },
        { $set: { resolvedPermissions: resolved.resolvedPermissions, version: (policy.version ?? 1) + 1, meta: touchMeta(policy.meta) } },
      );
      resynced += 1;
    }
    return resynced;
  }
}

/** Re-exported so a caller validating a fixture does not import the vocabulary from two places. */
export type { PolicyConditionKey };
