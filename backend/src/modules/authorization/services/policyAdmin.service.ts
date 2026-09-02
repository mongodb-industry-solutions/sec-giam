import { Db } from 'mongodb';
import { v4 as uuidv4 } from 'uuid';
import { POLICY_COLLECTION } from '../../../shared/models/collections';
import { newMeta, touchMeta } from '../../../shared/models/base.model';
import {
  PolicyRecord, PolicyCondition, POLICY_CONDITION_KEYS, PolicyConditionKey, isInEffect,
} from '../models/policy.model';
import { parsePermission } from '../models/resource.model';

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
  permissionCount: number;
  conditionCount: number;
  /** False while a policy is drafted or dated ahead, so a list shows what actually decides today. */
  inEffect: boolean;
  attachedTo: string[];
  created?: string;
  lastModified?: string;
}

export interface PolicyDetail extends PolicySummary {
  permissions: string[];
  resource: PolicyRecord['resource'];
  principals?: string[];
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
 * Checked here as well as in the request schema on purpose. The schema protects the HTTP surface; a
 * seeder and any future caller reach the collection through this class, and a rule enforced in only
 * one of the two is a rule with a way around it.
 */
export function validatePolicy(policy: {
  effect?: 'allow' | 'deny';
  permissions?: string[];
  resource?: { type: string; pattern: string };
  conditions?: PolicyCondition[];
}): PolicyRefusal | null {
  if (policy.effect !== 'allow' && policy.effect !== 'deny') {
    return {
      status: 400,
      title: 'Unknown effect',
      detail: `A policy names effect "${policy.effect}". Only allow and deny exist.`,
    };
  }

  if (!policy.permissions?.length) {
    return {
      status: 400,
      title: 'Policy governs nothing',
      detail:
        'A policy with no permission decides nothing and would sit in the list looking as though '
        + 'it did. Name at least one permission, as `resource:action`.',
    };
  }

  for (const permission of policy.permissions) {
    // A permission is `resource:action` everywhere it appears, so a policy naming something that is
    // not one would never match a request, however the request was spelled.
    if (permission !== '*' && !parsePermission(permission)) {
      return {
        status: 400,
        title: 'Not a permission',
        detail:
          `"${permission}" is not of the form resource:action. That is the one spelling a role, a `
          + 'policy and a token all use, so a policy written another way matches nothing.',
      };
    }
  }

  if (!policy.resource?.type || !policy.resource?.pattern) {
    return {
      status: 400,
      title: 'Policy names no resource',
      detail: 'A policy states what it governs: a resource type, and the pattern an object must match.',
    };
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
  }
  return null;
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
      permissionCount: (policy.permissions ?? []).length,
      conditionCount: (policy.conditions ?? []).length,
      inEffect: isInEffect(policy),
      attachedTo: policy.attachedTo ?? [],
      ...(policy.meta?.created ? { created: policy.meta.created } : {}),
      ...(policy.meta?.lastModified ? { lastModified: policy.meta.lastModified } : {}),
    };
  }

  async list(
    realmId: string,
    options: { q?: string; skip?: number; limit?: number } = {},
  ): Promise<{ policies: PolicySummary[]; total: number }> {
    const skip = Math.max(0, options.skip ?? 0);
    const limit = Math.min(200, Math.max(1, options.limit ?? 20));
    const filter: Record<string, unknown> = { realmId };
    if (options.q) {
      // Anchored on the two fields a person would search by. Escaped, because a search box is not a
      // place to accept an expression the database will then run.
      const escaped = options.q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { name: { $regex: escaped, $options: 'i' } },
        { version: { $regex: escaped, $options: 'i' } },
      ];
    }

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
      permissions: policy.permissions ?? [],
      resource: policy.resource,
      conditions: policy.conditions ?? [],
      ...(policy.principals ? { principals: policy.principals } : {}),
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
      effect: 'allow' | 'deny'; permissions: string[]; resource: PolicyRecord['resource'];
      principals?: string[]; conditions?: PolicyCondition[];
      obligations?: PolicyRecord['obligations']; approvedBy?: string; effectiveFrom?: string;
      reason?: string; attachedTo?: string[];
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
      permissions: input.permissions,
      resource: input.resource,
      conditions: input.conditions ?? [],
      ...(input.principals?.length ? { principals: input.principals } : {}),
      ...(input.obligations?.length ? { obligations: input.obligations } : {}),
      ...(input.approvedBy ? { approvedBy: input.approvedBy } : {}),
      ...(input.effectiveFrom ? { effectiveFrom: input.effectiveFrom } : {}),
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.attachedTo?.length ? { attachedTo: input.attachedTo } : {}),
      meta: newMeta('Policy'),
    });
    return await this.detail(realmId, policyId) as PolicyDetail;
  }

  /**
   * Partial, and every list is replaced rather than merged.
   *
   * A policy is a statement of what it says, so merging would make removing a permission or a
   * condition impossible from here, and a deny nobody can delete is worse than one nobody can add.
   */
  async update(
    realmId: string,
    policyId: string,
    patch: {
      version?: number; status?: PolicyRecord['status']; effect?: 'allow' | 'deny';
      permissions?: string[]; resource?: PolicyRecord['resource']; principals?: string[];
      conditions?: PolicyCondition[]; obligations?: PolicyRecord['obligations'];
      approvedBy?: string; effectiveFrom?: string; reason?: string; attachedTo?: string[];
    },
  ): Promise<PolicyDetail | PolicyRefusal | null> {
    const policy = await this.policies.findOne({ realmId, policyId }, { projection: { _id: 0 } });
    if (!policy) return null;

    const changes: Partial<PolicyRecord> = {};
    for (const field of [
      'version', 'status', 'effect', 'permissions', 'resource', 'principals',
      'obligations', 'approvedBy', 'effectiveFrom', 'reason', 'attachedTo', 'conditions',
    ] as const) {
      if (patch[field] !== undefined) (changes as Record<string, unknown>)[field] = patch[field];
    }

    // Validated against the MERGED policy, so a patch cannot slip a condition past the vocabulary
    // by sending it without the fields the check reads beside it.
    const invalid = validatePolicy({ ...policy, ...changes });
    if (invalid) return invalid;

    if (Object.keys(changes).length > 0) {
      await this.policies.updateOne({ realmId, policyId }, { $set: { ...changes, meta: touchMeta(policy.meta) } });
    }
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
}

/** Re-exported so a caller validating a fixture does not import the vocabulary from two places. */
export type { PolicyConditionKey };
