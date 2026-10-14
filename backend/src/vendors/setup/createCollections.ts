import { Db } from 'mongodb';
import { isUnsupportedQueryTypeError } from '@ist-sec/mongo-compat';
import { GIAM_COLLECTIONS, AUDIT_COLLECTION } from '../../shared/models/collections';
import { buildEncryptedFieldsMaps, GiamDeks } from '../encryption/encryptedFieldsMaps';
import { capabilities, describeDeployment } from '../mongodb/deployment';
import { config } from '../../config';

/**
 * Creates every collection from the canonical registry.
 *
 * Driven by the registry rather than by a list here, so a collection cannot exist in the database
 * without an owning module recorded next to it.
 *
 * Note the trap this project has paid for before: setup SKIPS a collection that already exists, so a
 * collection created once with the wrong encryptedFields keeps them until it is dropped. Changing an
 * encrypted-fields map needs `--reset`, and the runbook says so.
 */
export async function createCollections(db: Db, deks: GiamDeks, reset = false): Promise<void> {
  /**
   * Refuse before creating anything, on a deployment that cannot encrypt.
   *
   * Gated on AUTOMATIC encryption and not merely on Queryable Encryption. Community can hold a QE
   * collection but cannot analyse a query against one, so setup would succeed, the seeder would
   * write, and every principal read would then fail on a database that looks correctly built. The
   * failure belongs here, where one corrected variable fixes it, and not at the first login.
   */
  if (!capabilities().automaticEncryption) {
    throw new Error(
      `${describeDeployment()} cannot perform automatic Queryable Encryption, and GIAM will not `
      + 'create a principal collection it could never read.\n'
      + '  Point GIAM_DB_URI / MONGODB_URI at Atlas or Enterprise Advanced 7.0+, and correct '
      + 'MONGODB_TYPE / MONGODB_VERSION to match.',
    );
  }

  const existing = new Set((await db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name));
  const maps = buildEncryptedFieldsMaps(deks);

  /**
   * On `--reset`, drop collections the registry NO LONGER NAMES as well as the ones it does.
   *
   * Without this the loop below only ever touches registered collections, so a collection the model
   * has dropped or renamed away survives every reset forever. That is not a cosmetic leftover: its
   * `encryptedFields` still reference DEKs the rebuilt vault no longer holds, so validation reports
   * a stale DEK on a collection nothing reads, and "rebuild with --reset" does not fix it because
   * the reset is exactly what skips it.
   *
   * Guarded to `reset`, so an ordinary setup run never removes anything.
   */
  if (reset) {
    const registered = new Set<string>(GIAM_COLLECTIONS.map((spec) => spec.name));
    for (const name of existing) {
      if (registered.has(name)) continue;
      /**
       * The driver's encrypted-state collections go with their parent, not on their own.
       *
       * Unless the parent is gone. `enxcol_.identity.esc` outlived `identity` through the rename to
       * `principal`, and a state collection whose parent no longer exists holds index metadata for
       * DEKs the rebuilt vault does not have. It is unreachable, unreadable and indistinguishable
       * from a live one to anybody auditing the database.
       */
      if (name.startsWith('enxcol_.')) {
        const parent = name.split('.')[1];
        if (parent && !registered.has(parent)) {
          await db.collection(name).drop();
          existing.delete(name);
          console.log(`  dropped: ${name} (encrypted state for a collection that is gone)`);
        }
        continue;
      }
      // The server's own namespaces, including the view a time series collection creates. Dropping
      // one is not permitted and is not ours to attempt.
      if (name.startsWith('system.')) continue;
      if (name === config.mongodb.keyVaultCollection) continue;
      await db.collection(name).drop();
      existing.delete(name);
      console.log(`  dropped: ${name} (the model no longer names it)`);
    }
  }

  for (const spec of GIAM_COLLECTIONS) {
    if (existing.has(spec.name) && !reset) {
      const note = spec.encrypted ? ' (already exists; encryptedFields changes need --reset)' : ' (already exists)';
      console.log(`  skip:    ${spec.name}${note}`);
      continue;
    }
    if (existing.has(spec.name)) {
      await db.collection(spec.name).drop();
      console.log(`  dropped: ${spec.name}`);
    }

    if (spec.kind === 'timeseries') {
      // Append-only, high volume, queried by range. Seconds granularity: security events arrive in
      // bursts around a sign-in, and a coarser bucket would put a whole login flow in one document.
      /**
       * Retention, applied at creation, from configuration.
       *
       * A time series collection expires on its own time field, so this needs no TTL index. Zero
       * disables it, for a deployment that archives externally and wants nothing removed here.
       *
       * Stated in the log because "long retention" was what the registry claimed while nothing
       * implemented it, and a deployment could not say what its retention actually was.
       */
      const retentionDays = config.app.auditRetentionDays;
      const expireAfterSeconds = retentionDays > 0 && capabilities().timeSeriesExpiry
        ? retentionDays * 86_400
        : undefined;
      if (retentionDays > 0 && !capabilities().timeSeriesExpiry) {
        console.warn(`  warn:    ${spec.name}: this server cannot expire a time series, so the `
          + `${retentionDays} day retention is NOT enforced. Evidence accumulates without limit.`);
      }
      await db.createCollection(spec.name, {
        timeseries: { timeField: 'ts', metaField: 'meta', granularity: 'seconds' },
        ...(expireAfterSeconds ? { expireAfterSeconds } : {}),
      });
      console.log(
        `  created: ${spec.name} (time series, ${expireAfterSeconds ? `${retentionDays} day retention` : 'no expiry'})`
        + ` (${spec.purpose})`,
      );
      continue;
    }

    if (spec.encrypted) {
      /**
       * Created with the declared map, and DEGRADED if the driver cannot support it.
       *
       * `encryptedFieldsMaps` claims that on an older cluster the substring field "degrades to
       * equality rather than failing setup". That was not true: the choice was made from a static
       * configuration flag, so a deployment whose `crypt_shared` predates the substring query type
       * failed here instead, leaving `principal` uncreated, unindexed and unencrypted. `setup:db`
       * then reported `requires-reset` forever, because the reset is what had failed.
       *
       * The claim is now true. A refusal naming the query type is caught, the map is rebuilt with
       * equality, and the loss of capability is stated rather than silent: administrative search by
       * name FRAGMENT stops working, and somebody has to know that rather than discover it.
       */
      try {
        await db.createCollection(spec.name, { encryptedFields: maps[spec.name] as never });
        console.log(`  created: ${spec.name} (QE) (${spec.purpose})`);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!isUnsupportedQueryTypeError(message)) throw err;

        console.warn(
          `  warn:    ${spec.name}: this driver refuses the declared query type, so the encrypted `
          + 'name field falls back to equality. Search by name FRAGMENT will not work until '
          + 'crypt_shared and the server support it.',
        );
        const degraded = buildEncryptedFieldsMaps(deks, { forceEquality: true });
        await db.createCollection(spec.name, { encryptedFields: degraded[spec.name] as never });
        console.log(`  created: ${spec.name} (QE, equality only) (${spec.purpose})`);
      }
      continue;
    }

    await db.createCollection(spec.name);
    console.log(`  created: ${spec.name} (${spec.purpose})`);
  }

  // Stated rather than assumed: the audit collection is the one that must never be created plain, or
  // a range query over it would work and a reviewer would never learn it is not a time series.
  if (!existing.has(AUDIT_COLLECTION) || reset) {
    console.log(`  note:    ${AUDIT_COLLECTION} is a time series; it cannot be converted in place`);
  }
}
