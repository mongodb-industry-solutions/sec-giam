import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * A callable capability an agent may be granted.
 *
 * The reason this is a record rather than a string in a policy is the normalized action. A policy
 * that says "may not refund" and a tool that calls itself `issueRefund` do not match, and nobody
 * finds out until the policy silently fails to apply. Naming the actions here, once, means a policy
 * references a stable identifier and the tool's own naming can change without breaking it.
 */

/** How much a mistake costs. Used to decide what a call needs, never to decide it on its own. */
export type ToolRiskClass = 'low' | 'moderate' | 'high' | 'critical';

export interface ToolRecord extends Scoped {
  toolId: string;
  name: string;
  description?: string;

  /**
   * The stable action names a policy is written against.
   *
   * Deliberately not the tool's own method names: those belong to whoever wrote the tool and change
   * when they refactor. These belong to the policy vocabulary and change only when the meaning does.
   */
  normalizedActions: string[];

  /** Which resource server enforces calls to it, so a permission here means the same thing there. */
  resourceServerId?: string;
  endpoint?: string;

  /**
   * Risk class, which informs what a call requires rather than deciding it.
   *
   * A critical tool is where a delegated token bound to one transaction, a short expiry and a fresh
   * authorisation stop being over-engineering. Recording the class is what lets that be policy
   * instead of a judgement someone makes per integration.
   */
  riskClass: ToolRiskClass;

  owner: {
    kind: 'application' | 'tenant' | 'person' | 'team';
    ref: string;
    displayName?: string;
  };

  status: 'active' | 'deprecated' | 'withdrawn';
  meta: Meta;
}

/**
 * A Model Context Protocol server: a host exposing tools and context to agents.
 *
 * Separate from the tools it exposes because the trust questions differ. A tool is "may this action
 * be taken"; a server is "is this endpoint who it claims to be, and over what transport". A server
 * going out of service must not silently un-approve the tools it happened to host.
 */
export interface McpServerRecord extends Scoped {
  mcpServerId: string;
  name: string;
  endpoint: string;
  transport: 'stdio' | 'http' | 'sse' | 'websocket';
  /** How this authority proves itself to the server, and the server to it. */
  authScheme: 'none' | 'bearer' | 'mtls' | 'oauth';
  exposedToolIds: string[];
  status: 'active' | 'unreachable' | 'withdrawn';
  meta: Meta;
}

/** Whether a tool may be called at all, before any question of who is calling it. */
export function isCallable(tool: Pick<ToolRecord, 'status'>): boolean {
  return tool.status === 'active';
}

/**
 * Whether an action is one this tool declares.
 *
 * An undeclared action is refused rather than allowed through as an unknown: a tool that can be
 * asked to do something nobody wrote down is a tool whose policy cannot be complete.
 */
export function declares(tool: Pick<ToolRecord, 'normalizedActions'>, action: string): boolean {
  return tool.normalizedActions.includes(action);
}

/** Where the cost of being wrong justifies binding a token to one task and one short window. */
export function requiresTransactionBinding(tool: Pick<ToolRecord, 'riskClass'>): boolean {
  return tool.riskClass === 'high' || tool.riskClass === 'critical';
}
