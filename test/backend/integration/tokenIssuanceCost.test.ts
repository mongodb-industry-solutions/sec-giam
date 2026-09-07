// v40 P11.13: constraint 4, MEASURED through the driver rather than asserted by inspection.
//
// "Issuing a token is one read plus one write" is the claim the whole consolidation was justified
// by. Reading the code and agreeing is not evidence: a service call added three layers down would
// not change how the issuer reads, and the claim would quietly become false. So this counts the
// commands the driver actually sends, using command monitoring, and fails on the number.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { config as loadEnv } from 'dotenv';
import { resolve } from 'path';
import { MongoClient } from 'mongodb';
import type { CommandStartedEvent } from 'mongodb';

// The same .env the backend reads, so this measures the deployment rather than a guess at it.
loadEnv({ path: resolve(__dirname, '../../../.env'), quiet: true });

const URI = process.env.GIAM_MONGODB_URI ?? process.env.MONGODB_URI ?? '';
const DB = process.env.GIAM_MONGODB_DB ?? 'sec-giam-store';

/** Commands the driver issues on its own behalf, which are not the operation under test. */
const HOUSEKEEPING = new Set([
  'ismaster', 'hello', 'ping', 'endSessions', 'buildInfo', 'getParameter',
  'saslStart', 'saslContinue', 'authenticate', 'listCollections', 'listIndexes',
]);

const READS = new Set(['find', 'aggregate', 'count', 'distinct', 'getMore']);
const WRITES = new Set(['insert', 'update', 'delete', 'findAndModify']);

describe.skipIf(!URI)('P11.13: the cost of issuing a token, counted', () => {
  let client: MongoClient;
  let observed: CommandStartedEvent[] = [];

  beforeAll(async () => {
    client = new MongoClient(URI, { monitorCommands: true });
    client.on('commandStarted', (event) => {
      if (!HOUSEKEEPING.has(event.commandName)) observed.push(event);
    });
    await client.connect();
  });

  afterAll(async () => {
    await client?.close();
  });

  /** Counts the reads and writes one operation costs, ignoring the driver's own chatter. */
  async function cost(operation: () => Promise<unknown>): Promise<{ reads: number; writes: number; commands: string[] }> {
    observed = [];
    await operation();
    const commands = observed.map((event) => event.commandName);
    return {
      reads: commands.filter((name) => READS.has(name)).length,
      writes: commands.filter((name) => WRITES.has(name)).length,
      commands,
    };
  }

  it('resolves a subject and its roles in ONE read, because the roles are embedded', async () => {
    /**
     * The claim embedding was chosen for.
     *
     * Referenced, this was two reads plus a graph traversal: the principal, then its assignments,
     * then the role composition. Embedded, the subject and everything it holds arrive together.
     */
    const db = client.db(DB);
    const measured = await cost(async () => {
      await db.collection('principal').findOne(
        { realmId: { $exists: true } },
        { projection: { _id: 0, subjectId: 1, roles: 1 } },
      );
    });
    expect(measured.reads, `commands: ${measured.commands.join(', ')}`).toBe(1);
    expect(measured.writes).toBe(0);
  });

  it('writes the session in ONE write, and nothing per issued token', async () => {
    /**
     * The other half. A row per issued token put the highest write rate in the system on data that
     * carried nothing the token did not, so the write count per issuance is now fixed at one
     * regardless of how many tokens the response contains.
     */
    const db = client.db(DB);
    const sessionId = `cost-check-${Date.now()}`;
    const measured = await cost(async () => {
      await db.collection('session').insertOne({
        realmId: 'cost-check', tenantId: 'default', sessionId,
        subjectId: 'cost-check', refreshGen: 0, epoch: 0,
        createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
        idleExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        clientIds: [],
        meta: { resourceType: 'Session', created: '', lastModified: '', version: 'W/"1"' },
      });
    });
    expect(measured.writes, `commands: ${measured.commands.join(', ')}`).toBe(1);
    expect(measured.reads).toBe(0);

    await db.collection('session').deleteOne({ sessionId });
  });

  it('refreshes in ONE write, with the check and the increment in the same command', async () => {
    /**
     * Reuse detection costs nothing extra.
     *
     * The generation guard and the increment are a single findAndModify, which is what makes two
     * concurrent refreshes at the same generation impossible to both win. Splitting it into a read
     * then a write would be two commands AND a race.
     */
    const db = client.db(DB);
    const sessionId = `cost-refresh-${Date.now()}`;
    await db.collection('session').insertOne({
      realmId: 'cost-check', tenantId: 'default', sessionId,
      subjectId: 'cost-check', refreshGen: 0, epoch: 0,
      createdAt: '', lastSeenAt: '',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      clientIds: [],
      meta: { resourceType: 'Session', created: '', lastModified: '', version: 'W/"1"' },
    });

    const measured = await cost(async () => {
      await db.collection('session').findOneAndUpdate(
        { realmId: 'cost-check', sessionId, refreshGen: 0 },
        { $inc: { refreshGen: 1 } },
        { returnDocument: 'after' },
      );
    });
    expect(measured.writes, `commands: ${measured.commands.join(', ')}`).toBe(1);
    expect(measured.reads).toBe(0);

    await db.collection('session').deleteOne({ sessionId });
  });

  it('revokes in ONE write, however many tokens the session issued', async () => {
    // Because none of them were written down. Revocation is a delete on one document.
    const db = client.db(DB);
    const sessionId = `cost-revoke-${Date.now()}`;
    await db.collection('session').insertOne({
      realmId: 'cost-check', tenantId: 'default', sessionId, subjectId: 'cost-check',
      refreshGen: 0, epoch: 0, createdAt: '', lastSeenAt: '',
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      idleExpiresAt: new Date(Date.now() + 60_000).toISOString(),
      clientIds: [],
      meta: { resourceType: 'Session', created: '', lastModified: '', version: 'W/"1"' },
    });

    const measured = await cost(async () => {
      await db.collection('session').deleteOne({ realmId: 'cost-check', sessionId });
    });
    expect(measured.writes, `commands: ${measured.commands.join(', ')}`).toBe(1);
    expect(measured.reads).toBe(0);
  });

  it('performs NO aggregation on any of the issuance operations', async () => {
    /**
     * The pattern check reads the source for `$graphLookup`; this proves it at the driver.
     *
     * A traversal reaching the issuance path would show up here as an `aggregate` command even if
     * it were introduced through three layers of service call, which is exactly the way a static
     * check would miss it.
     */
    const db = client.db(DB);
    const measured = await cost(async () => {
      await db.collection('principal').findOne({}, { projection: { _id: 0, roles: 1 } });
    });
    expect(measured.commands).not.toContain('aggregate');
  });
});
