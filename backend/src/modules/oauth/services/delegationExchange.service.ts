import { Db } from 'mongodb';
import { DELEGATION_COLLECTION } from '../../../shared/models/collections';
import { DelegationRecord, isExercisable, narrowScope, chainDepth } from '../../consent/models/delegation.model';
import { RealmRecord } from '../../realm/models/realm.model';
import { ClientRecord } from '../models/client.model';
import { DecisionService } from '../../authorization/services/decision.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { ActorClaim } from '../models/token.model';

/**
 * Delegation at the token endpoint: acting FOR somebody, with your own identity intact.
 *
 * The five multi-hop rules are enforced here rather than described in a document, because a rule
 * enforced by convention is one that holds until somebody adds a fourth hop in a hurry:
 *
 * 1. Scope is intersected, never unioned. A downstream token cannot broaden what it came from.
 * 2. Each hop APPENDS to the actor chain. It is never truncated or rewritten.
 * 3. Depth is bounded per realm, and a token exceeding it is refused.
 * 4. Every hop is authorised independently. Agent B does not inherit authority from Agent A.
 * 5. Authority bound to a transaction is usable only for that transaction.
 *
 * Rule 4 is the one that is easy to get wrong and expensive to get wrong: it is tempting to treat a
 * valid inbound token as proof that the next hop is fine, and that is precisely how a chain ends up
 * carrying authority nobody granted.
 */

const DEFAULT_MAX_CHAIN_DEPTH = 3;

export interface DelegationRefusal {
  status: number;
  error: string;
  description?: string;
}

export interface DelegationOutcome {
  subjectId: string;
  scope: string[];
  actor: ActorClaim;
  delegation: DelegationRecord;
}

export function isDelegationRefusal(value: unknown): value is DelegationRefusal {
  return typeof value === 'object' && value !== null && 'error' in value && 'status' in value;
}

export class DelegationExchangeService {
  constructor(private readonly db: Db) {}

  private get delegations() {
    return this.db.collection<DelegationRecord>(DELEGATION_COLLECTION);
  }

  /**
   * Authorises one hop.
   *
   * `presented` is the verified inbound token's claims: its subject, its scope, and the chain it
   * already carries.
   */
  async authorizeHop(
    realm: RealmRecord,
    client: ClientRecord,
    presented: { subjectId: string; scope: string[]; actor?: ActorClaim },
    requested: { scope: string[]; transactionId?: string },
  ): Promise<DelegationOutcome | DelegationRefusal> {
    const refuse = (cause: string): DelegationRefusal => {
      void new SecurityEventService(this.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authorization',
        action: 'token.delegation',
        outcome: 'failure',
        clientId: client.clientId,
        subjectId: presented.subjectId,
        cause,
        principalSubjectId: presented.subjectId,
        agentId: client.clientId,
        decision: 'deny',
        ...(requested.transactionId ? { transactionId: requested.transactionId } : {}),
        detail: { transactionId: requested.transactionId },
      });
      // One answer for every refusal. Distinguishing "no delegation" from "expired" from "too deep"
      // tells a caller how to probe the chain, and none of it helps a legitimate one.
      return { status: 400, error: 'invalid_grant', description: 'That delegation is not permitted.' };
    };

    // Rule 3, before anything else is read: a chain that is already too long cannot be extended by
    // finding a valid delegation at the end of it.
    const bound = (realm as RealmRecord & { maxDelegationDepth?: number }).maxDelegationDepth
      ?? DEFAULT_MAX_CHAIN_DEPTH;
    if (chainDepth(presented.actor) >= bound) return refuse('chain_depth_exceeded');

    const delegation = await this.delegations.findOne(
      { realmId: realm.realmId, principalSubjectId: presented.subjectId, agentId: client.clientId },
      { projection: { _id: 0 } },
    );
    if (!delegation) return refuse('no_delegation');
    if (!isExercisable(delegation)) return refuse('delegation_not_exercisable');

    // Rule 5. Authority bound to one task is useless for another, which is the difference between
    // "may move money for this payment" and "may move money".
    if (delegation.transactionId && delegation.transactionId !== requested.transactionId) {
      return refuse('transaction_mismatch');
    }

    // Rule 3 again, from the delegation's own side: the grantor said how far this may travel.
    if (chainDepth(presented.actor) > delegation.maxDepth) return refuse('delegation_depth_exceeded');

    // Rule 1, twice over. Narrowed against what the delegation permits AND against what the inbound
    // token actually carried, because a delegation cannot lend authority its holder did not present.
    const permitted = narrowScope(delegation.scope, requested.scope);
    const effective = narrowScope(presented.scope, permitted);
    if (effective.length === 0) return refuse('no_scope_remains');

    // Rule 4. This hop is authorised on its own evidence, not because the previous one was valid.
    const decision = await new DecisionService(this.db)
      .check(realm.realmId, client.clientId, client.clientId, 'delegation', 'exercise');
    if (decision.effect !== 'allow') return refuse('delegate_lacks_permission');

    void this.delegations.updateOne(
      { delegationId: delegation.delegationId },
      { $set: { lastUsedAt: new Date().toISOString() } },
    );

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action: 'token.delegation',
      outcome: 'success',
      clientId: client.clientId,
      subjectId: presented.subjectId,
      target: { type: 'delegation', ref: delegation.delegationId },
      // The chain, named field by field. This is the record that answers, later, which human
      // authorised the action and which agent actually took it.
      principalSubjectId: delegation.principalSubjectId,
      agentId: delegation.agentId,
      delegationId: delegation.delegationId,
      ...(requested.transactionId ? { transactionId: requested.transactionId } : {}),
      decision: 'allow',
      detail: { purpose: delegation.purpose, scope: effective, depth: chainDepth(presented.actor) + 1 },
    });

    return {
      // The SUBJECT stays the person. That is what makes this delegation rather than impersonation,
      // and what lets a downstream system see both who it is for and who is doing it.
      subjectId: presented.subjectId,
      scope: effective,
      // Rule 2: appended, with the existing chain carried underneath untouched.
      actor: {
        subjectId: client.clientId,
        clientId: client.clientId,
        ...(presented.actor ? { actor: presented.actor } : {}),
      },
      delegation,
    };
  }
}
