import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { Db } from 'mongodb';
import { getQEClient, closeQEClient } from '../vendors/encryption/qeClient';
import { initEventBus, getEventBus } from '../vendors/eventbus';
import { config } from '../config';

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
  await initEventBus(db).start();
}

async function teardownRuntime(): Promise<void> {
  try {
    await getEventBus().stop().catch(() => {});
  } catch { /* bus not initialised */ }
  await closeQEClient();
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
