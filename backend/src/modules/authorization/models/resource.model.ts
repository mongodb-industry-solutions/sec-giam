import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * Every protected object, and the action catalog it declares.
 *
 * One collection for an API, a tool and a Model Context Protocol server, because they are the same
 * kind of thing: something a decision is made ABOUT. An agent invoking a tool then goes through the
 * same decision function as a person reading an account, which is the point. A separate mechanism
 * for tools would be a second authorization system with its own vocabulary, its own conditions and
 * its own audit trail, and the two would be free to disagree about whether something was allowed.
 *
 * A resource may CONTAIN resources, through `parentResourceId`, so a server exposing tools needs no
 * collection of its own and no join table to say which tools it offers.
 */

export type ResourceKind = 'api' | 'tool' | 'mcp_server' | 'object';

/** How a resource verifies a token, where it verifies one at all. */
export type ValidationMode = 'local-jwks' | 'introspection' | 'hybrid';

export interface ResourceRecord extends Scoped {
  resourceId: string;
  kind: ResourceKind;
  name: string;
  displayName?: string;
  description?: string;

  /**
   * What a token must name in `aud` to be accepted here. Only an `api` has one.
   *
   * Sparse rather than required, because a tool is reached THROUGH a server that has an audience
   * and does not carry one itself.
   */
  audience?: string;

  /** The server or API a resource belongs to. Absent for a top-level one. */
  parentResourceId?: string;

  /**
   * The verbs this resource offers. The vocabulary every permission naming it is checked against.
   *
   * Bounded by what the application actually implements, replaced as a BLOCK at deploy time rather
   * than edited row by row, and read with the resource. Without a catalog a typo in a policy is a
   * rule that never fires and nobody ever finds out; with one, the write is refused at the point
   * somebody made the mistake.
   */
  actions: string[];
  /** Bumped whenever `actions` changes, so drift is visible rather than silent. */
  catalogVersion: number;

  /**
   * The SCOPES this resource server accepts, and what each one means to a person.
   *
   * Here rather than in code, and that is not a preference. A description like "See your payments"
   * is one industry's vocabulary, and this authority must serve several: a map of scope names to
   * sentences compiled into the service would be exactly what `dayOneInvariants.test.ts` refuses.
   * The deployment declares them, through setup and the seeder, and GIAM renders what it is given.
   *
   * The descriptions were previously a constant in the CONSENT SCREEN, which put them outside the
   * API entirely: a person calling the authority directly could not learn what they were agreeing
   * to, and two clients could describe one scope differently.
   *
   * `required` marks a scope the flow cannot proceed without. Declining one ends the flow with
   * `access_denied` rather than producing a token missing something it needs.
   */
  scopes?: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;

  /**
   * How this resource verifies a token.
   *
   * Local verification against the published key set costs nothing per request and keeps the
   * application serving when the authority is unreachable. Introspection is authoritative about
   * revocation and current status. Neither is right in general, so the choice belongs to the
   * resource.
   */
  validationMode?: ValidationMode;

  /** For a tool or a server: where it is actually reached. */
  endpoint?: string;
  transport?: 'stdio' | 'http' | 'sse' | 'websocket';
  authScheme?: 'none' | 'bearer' | 'mtls' | 'oauth';

  /**
   * How much damage calling this wrongly does. Carried, never interpreted here.
   *
   * This authority decides WHETHER a caller may act. What risk class a capability carries, and what
   * controls that implies, belongs to the system that governs the business risk. Recording it makes
   * the decision auditable without making this service the arbiter of it.
   */
  riskClass?: 'low' | 'moderate' | 'high' | 'critical';

  /** SSF/CAEP delivery for a resource that wants to hear about revocations. Bounded, so no collection. */
  signalStream?: {
    deliveryMethod: 'push' | 'poll';
    endpoint?: string;
    events: string[];
  };

  status: 'active' | 'deprecated' | 'withdrawn';
  registeredAt?: string;
  meta: Meta;
}

/** Whether a resource may be reached at all. Absence of `active` is refusal, never permission. */
export function isReachable(resource: Pick<ResourceRecord, 'status'>): boolean {
  return resource.status === 'active';
}

/**
 * Whether a resource declares this verb.
 *
 * The catalog check, and the reason the catalog is on the resource: a resource knows its own verbs,
 * the list is bounded, and it is read with the resource anyway.
 */
export function declaresAction(
  resource: Pick<ResourceRecord, 'actions'>,
  action: string,
): boolean {
  return resource.actions.includes(action);
}

/**
 * A permission string, `resource:action`.
 *
 * A permission is VOCABULARY rather than a row. It appears on a role, on a policy and in a token,
 * and in all three it is this string, so there is one spelling and nothing to keep in step.
 */
export function permissionString(resourceType: string, action: string): string {
  return `${resourceType}:${action}`;
}

/** Splits a permission string back into its halves, or null when it is not one. */
export function parsePermission(permission: string): { resource: string; action: string } | null {
  const separator = permission.indexOf(':');
  if (separator <= 0 || separator === permission.length - 1) return null;
  return {
    resource: permission.slice(0, separator),
    action: permission.slice(separator + 1),
  };
}
