import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { Db } from 'mongodb';
import * as dotenv from 'dotenv';
import { resolve } from 'path';
import { getQEClient, closeQEClient } from '../vendors/encryption/qeClient';
import { initEventBus, getEventBus } from '../vendors/eventbus';
import { bindPolicyEvaluators } from '../modules/authorization/services/policyEvaluators';
import { SessionWatch } from '../modules/authorization/services/sessionWatch';
import { config, keyVaultNamespace } from '../config';

declare module 'fastify' {
  interface FastifyInstance {
    // Always typed as Db; check fastify.dbError for connection health.
    db: Db;
    // null = connected; non-null string = reason, credentials stripped.
    dbError: string | null;
  }
}

// Never log credentials: the reason is echoed in the health response.
function sanitizeUri(uri: string): { server: string; database: string } {
  try {
    const clean = uri.replace(/^(mongodb(?:\+srv)?:\/\/)([^@]+@)/, '$1');
    return { server: new URL(clean).hostname || 'unknown', database: config.mongodb.dbName };
  } catch {
    return { server: 'unknown', database: config.mongodb.dbName };
  }
}

async function connectAndWire(fastify: FastifyInstance): Promise<void> {
  const client = await getQEClient();
  const db = client.db(config.mongodb.dbName);
  fastify.db = db;
  fastify.dbError = null;
  // Here rather than at registration, so a reload re-binds too: the policy evaluator reads the
  // collection directly, and leaving it bound to a torn-down client would fail every decision.
  bindPolicyEvaluators(db);

  /**
   * P10.4, layer 2 of revocation propagation.
   *
   * Started HERE for the same reason the evaluators are bound here: a reload has to rebuild it. A
   * watch left pointing at a torn-down client stops receiving changes and keeps answering from
   * whatever it last saw, which is a cache that silently honours revoked sessions.
   *
   * Failure to start is not fatal. A change stream needs a replica set, and a single-node
   * deployment has none; the authoritative read still works and layer 1, the five minute token
   * lifetime, is always in force. Refusing to boot over an optional cache would be worse than
   * running without it.
   */
  await stopSessionWatch();
  sessionWatch = new SessionWatch(db);
  try {
    await sessionWatch.start();
  } catch {
    // Recorded by the caller's startup report rather than thrown: the cache is an optimisation and
    // `isLive` returns null while it is unready, which callers already treat as "go and read".
    sessionWatch = null;
  }

  await initEventBus(db).start();
}

/** The live-session cache, when one could be started. Null on a deployment without a replica set. */
let sessionWatch: SessionWatch | null = null;

export function getSessionWatch(): SessionWatch | null {
  return sessionWatch;
}

async function stopSessionWatch(): Promise<void> {
  await sessionWatch?.stop().catch(() => {});
  sessionWatch = null;
}

async function teardownRuntime(): Promise<void> {
  await stopSessionWatch();
  try {
    await getEventBus().stop().catch(() => {});
  } catch { /* bus not initialised */ }
  await closeQEClient();
}

/**
 * Rebuilds the datastore runtime in place, without restarting the process.
 *
 * A drop plus a setup plus a seed leaves this process holding a client bound to a key vault that no
 * longer exists, and every encrypted read then fails with a driver-level message about unsatisfied
 * keys. On a host an operator can restart that is a restart; on one they cannot, this is the only way
 * back, and it is deliberately independent of the restart route.
 */
export async function reloadDbRuntime(fastify: FastifyInstance): Promise<{ steps: string[] }> {
  const steps: string[] = [];
  const started = Date.now();

  // The same candidates the process started from, so a reload cannot read a different file than the
  // boot did. A missing one is not an error: a container is configured through injected variables.
  const candidates = ['../.env', '../../.env', '../../../.env'].map((p) => resolve(__dirname, p));
  const result = dotenv.config({ path: candidates, override: true });
  steps.push(result.error
    ? 'no .env found, continuing with the current process environment'
    : `.env reloaded (${Object.keys(result.parsed ?? {}).length} variable(s))`);

  await teardownRuntime();
  steps.push('torn down: event bus and the cached encrypted client');
  await connectAndWire(fastify);
  steps.push(`re-wired against database "${config.mongodb.dbName}"`);

  try {
    const dekCount = await fastify.db.collection(config.mongodb.keyVaultCollection).countDocuments();
    steps.push(`key vault ${keyVaultNamespace()}: ${dekCount} key(s) available`);
  } catch (err) {
    steps.push(`key vault check skipped: ${err instanceof Error ? err.message : String(err)}`);
  }

  steps.push(`reload complete in ${Date.now() - started}ms`);
  return { steps };
}

// Fault tolerant on purpose: the process still starts so the health and posture endpoints can report
// WHY it is degraded. An identity service that refuses to boot tells an operator nothing.
async function mongodbPlugin(fastify: FastifyInstance) {
  fastify.decorate('db', null as unknown as Db);
  fastify.decorate('dbError', null as string | null);

  if (!config.mongodb.uri) {
    const msg = 'GIAM_DB_URI / MONGODB_URI is not set; GIAM starting in degraded mode';
    console.error(`[giam/mongodb] ${msg}`);
    fastify.dbError = msg;
    return;
  }

  try {
    await connectAndWire(fastify);
    fastify.addHook('onClose', teardownRuntime);
  } catch (err) {
    const { server, database } = sanitizeUri(config.mongodb.uri);
    const reason = err instanceof Error ? err.message : String(err);
    // The full reason goes to the log, which is behind the administrative credential. What the health
    // response carries is the host and the database and nothing else, in every deployment alike: a
    // driver message can name an internal host or a replica set, and whether that is safe to publish
    // does not depend on which environment this happens to be.
    console.error(`[giam/mongodb] Connection failed: server=${server} database=${database}. ${reason}`);
    fastify.dbError = `Connection failed: server=${server} database=${database}`;
  }
}

export default fp(mongodbPlugin, { name: 'mongodb' });
