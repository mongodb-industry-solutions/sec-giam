import { Db } from 'mongodb';
import {
  AUDIT_COLLECTION, SESSION_COLLECTION, GRANT_COLLECTION, PRINCIPAL_COLLECTION,
} from '../../../shared/models/collections';
import { AuditRecord } from '../models/audit.model';

/**
 * One authorization flow, assembled.
 *
 * An audit almost always starts from a captured access token: decompose it, read `txn`, and ask what
 * happened. Answering that took five separate reads with five permission checks and a caller
 * stitching evidence together, which is not an answer a regulator can obtain with an HTTP client.
 *
 * ONE AGGREGATION, and the direction is not incidental. The pipeline starts on the audit collection,
 * which is a time series, and `$lookup`s into ordinary collections. The reverse, using a time series
 * collection as a lookup TARGET, is not something to rely on.
 *
 * What it deliberately does not do is decide who may read it. That check belongs in the controller,
 * before this runs: an aggregation is not a place to enforce who sees what.
 */

export interface FlowToken {
  jti: string;
  at: string;
  action: string;
  scope?: string[];
  grantType?: string;
}

export interface FlowAudit {
  txn: string;
  events: Array<{
    ts: string;
    action: string;
    outcome: string;
    cause?: string;
    subjectId?: string;
    clientId?: string;
    detail?: Record<string, unknown>;
  }>;
  tokens: FlowToken[];
  subjectId?: string;
  clientId?: string;
  /** What still exists and could be read. */
  session?: { sessionId: string; createdAt: string; expiresAt: string; acr?: string; amr?: string[] };
  grant?: { grantId: string; scope: string; status: string; grantedAt: string; revokedAt?: string };
  principal?: { subjectId: string; userName: string; displayName?: string; lifecycleState: string };
  credential?: { credentialId: string; type: string; assuranceLevel?: string };
  /**
   * What no longer exists, and WHY, stated rather than omitted.
   *
   * The ticket is TTL bounded in minutes by design, so any audit after the fact finds it gone. An
   * assembled view that simply left it out would read as though the flow had no authorization
   * request, which is a different and wrong story.
   */
  gone: Array<{ what: string; because: string }>;
}

export class FlowAuditService {
  constructor(private readonly db: Db) {}

  /**
   * Everything filed under one flow.
   *
   * Returns null when the flow has no events at all, which is how a caller learns a `txn` names
   * nothing rather than being handed an empty shell that looks like a flow with nothing in it.
   */
  async byTxn(realmId: string, txn: string): Promise<FlowAudit | null> {
    const pipeline = [
      { $match: { realmId, correlationId: txn } },
      { $sort: { ts: 1 } },
      {
        /**
         * Grouped so the lookups below run ONCE for the flow rather than once per event.
         *
         * A flow has a handful of events and each names the same subject and client, so joining
         * before grouping would repeat the same joins for every row.
         *
         * The pushed document is spelled out FIELD BY FIELD, and `$$ROOT` is deliberately not used.
         * The client this runs on is auto-encrypting, and Queryable Encryption's query analysis
         * refuses the variable outright: `Access to variable ROOT disallowed`. It fails at the
         * driver before the server sees it, so a plain client tests green and the application does
         * not, which is a difference worth stating rather than rediscovering.
         *
         * Naming the fields is better regardless: it keeps the pipeline's output to what the caller
         * is given rather than to whatever a row happens to hold.
         */
        $group: {
          _id: '$correlationId',
          events: {
            $push: {
              ts: '$ts',
              action: '$action',
              outcome: '$outcome',
              cause: '$cause',
              subjectId: '$meta.subjectId',
              clientId: '$meta.clientId',
              detail: '$detail',
            },
          },
          subjectId: { $first: '$meta.subjectId' },
          clientId: { $first: '$meta.clientId' },
        },
      },
      /**
       * The joins, in the SIMPLE form, and only into collections that are not encrypted.
       *
       * Two constraints of Queryable Encryption shape this, and both were found by running it:
       *
       * 1. A `$lookup` with a non-empty `let` is refused over an encrypted collection, so the
       *    correlated form with a sub-pipeline is not available. The plain
       *    `localField`/`foreignField` join is, and `subjectId` carries a globally unique index, so
       *    joining on it alone is exact rather than a compromise.
       * 2. `principal` is an encrypted collection and is NOT joined at all. That is the more
       *    important of the two and it is not a workaround: auto-decryption applies to the
       *    collection being queried, so a document pulled in by a join arrives with its encrypted
       *    fields still encrypted. A joined `name.formatted` would be ciphertext, which is worse
       *    than absent because it looks like data. It is read separately, through the same
       *    encrypting client, which is what decrypts it.
       */
      {
        $lookup: {
          from: SESSION_COLLECTION,
          localField: 'subjectId',
          foreignField: 'subjectId',
          as: 'sessions',
        },
      },
      {
        $lookup: {
          from: GRANT_COLLECTION,
          localField: 'subjectId',
          foreignField: 'subjectId',
          as: 'grants',
        },
      },
      {
        // The client is filtered HERE rather than in the join, since the simple form matches one
        // field pair. A subject may hold grants for several applications and only one is this flow.
        $addFields: {
          grants: {
            $filter: {
              input: '$grants',
              as: 'grant',
              cond: { $eq: ['$$grant.clientId', '$clientId'] },
            },
          },
        },
      },
    ];

    const [assembled] = await this.db
      .collection<AuditRecord>(AUDIT_COLLECTION)
      .aggregate(pipeline)
      .toArray() as Array<Record<string, unknown>>;

    if (!assembled) return null;

    type Projected = {
      ts: Date | string;
      action: string;
      outcome: string;
      cause?: string;
      subjectId?: string;
      clientId?: string;
      detail?: Record<string, unknown>;
    };
    const rows = assembled.events as Projected[];

    const events = rows.map((event) => ({
      ts: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
      action: event.action,
      outcome: event.outcome,
      ...(event.cause ? { cause: event.cause } : {}),
      ...(event.subjectId ? { subjectId: event.subjectId } : {}),
      ...(event.clientId ? { clientId: event.clientId } : {}),
      ...(event.detail ? { detail: event.detail } : {}),
    }));

    /**
     * The tokens the flow minted, from the events that recorded a `jti`.
     *
     * Read out of the trail rather than from a token store, because there is no token store: nothing
     * redeemable is kept at rest. The `jti` in the issuance event is the only record that a specific
     * token ever existed, which is why P1 started recording it.
     */
    const tokens: FlowToken[] = rows
      .filter((event) => typeof event.detail?.jti === 'string')
      .map((event) => ({
        jti: event.detail!.jti as string,
        at: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
        action: event.action,
        ...(Array.isArray(event.detail?.scope) ? { scope: event.detail!.scope as string[] } : {}),
        ...(typeof event.detail?.grantType === 'string' ? { grantType: event.detail!.grantType } : {}),
      }));

    const first = <T>(value: unknown): T | undefined => (Array.isArray(value) ? value[0] as T : undefined);
    const sessionRow = first<Record<string, unknown>>(assembled.sessions);
    const grantRow = first<Record<string, unknown>>(assembled.grants);

    const session = sessionRow
      ? {
        sessionId: sessionRow.sessionId as string,
        createdAt: String(sessionRow.createdAt ?? ''),
        expiresAt: String(sessionRow.expiresAt ?? ''),
        ...(sessionRow.acr ? { acr: sessionRow.acr as string } : {}),
        ...(sessionRow.amr ? { amr: sessionRow.amr as string[] } : {}),
      }
      : undefined;

    const grant = grantRow
      ? {
        grantId: grantRow.grantId as string,
        scope: String(grantRow.scope ?? ''),
        status: String(grantRow.status ?? ''),
        grantedAt: String(grantRow.grantedAt ?? ''),
        ...(grantRow.revokedAt ? { revokedAt: grantRow.revokedAt as string } : {}),
      }
      : undefined;

    /**
     * The principal, read on its own through the encrypting client.
     *
     * See the note on the joins: a `$lookup` into an encrypted collection returns its encrypted
     * fields still encrypted, so `name.formatted` would arrive as ciphertext. One indexed point read
     * is the correct shape here rather than a concession.
     */
    const subjectId = assembled.subjectId as string | undefined;
    const principalRow = subjectId
      ? await this.db.collection<{
        subjectId: string; userName: string; lifecycleState: string; name?: { formatted?: string };
      }>(PRINCIPAL_COLLECTION).findOne(
        { realmId, subjectId },
        { projection: { _id: 0, subjectId: 1, userName: 1, lifecycleState: 1, name: 1 } },
      )
      : null;

    /**
     * What is gone, and why. Absence with a reason is evidence; absence alone is a gap.
     */
    const gone: FlowAudit['gone'] = [];
    if (!session) {
      gone.push({
        what: 'session',
        because: 'no live session for this subject: it was ended, or it reached its own expiry',
      });
    }
    if (!grant) {
      gone.push({
        what: 'grant',
        because: 'no consent record: a first-party client or client_credentials creates none',
      });
    }
    gone.push({
      what: 'authorization request',
      because: 'the ticket is TTL bounded in minutes by design, so it is expected to be absent here. '
        + 'What it held is in the events, recorded when they were written',
    });

    return {
      txn,
      events,
      tokens,
      ...(assembled.subjectId ? { subjectId: assembled.subjectId as string } : {}),
      ...(assembled.clientId ? { clientId: assembled.clientId as string } : {}),
      ...(session ? { session } : {}),
      ...(grant ? { grant } : {}),
      ...(principalRow
        ? {
          principal: {
            subjectId: principalRow.subjectId,
            userName: principalRow.userName,
            ...(principalRow.name?.formatted ? { displayName: principalRow.name.formatted } : {}),
            lifecycleState: principalRow.lifecycleState,
          },
        }
        : {}),
      gone,
    };
  }

  /**
   * The flow one token belongs to, found by its `jti`.
   *
   * The entry point when somebody holds one token and nothing else. It answers with the correlator
   * rather than with the flow, so the caller makes the same permission-checked request anybody else
   * would: this is a lookup, not a second way in.
   */
  async txnForJti(realmId: string, jti: string): Promise<{ txn: string; at: string } | null> {
    const [event] = await this.db
      .collection<AuditRecord>(AUDIT_COLLECTION)
      .find({ realmId, 'detail.jti': jti }, { projection: { _id: 0, correlationId: 1, ts: 1 } })
      .limit(1)
      .toArray();
    if (!event?.correlationId) return null;
    return {
      txn: event.correlationId,
      at: event.ts instanceof Date ? event.ts.toISOString() : String(event.ts),
    };
  }
}

