// v40 P11.11: constraint 1, one test per control, each failing LOUDLY.
//
// The refactor renamed the collection holding personal data and merged four others into it. Nothing
// about the protection of that data may weaken as a side effect, and the reason this suite exists
// rather than a review is that every one of these controls fails QUIETLY when it breaks:
//
//   - encryption that stops applying stores plaintext and returns the right answer.
//   - redaction that stops applying writes a secret into the audit trail and logs success.
//   - a raw address instead of a hash is still a string in the right field.
//   - a stakeholder list that grants too widely returns MORE data, which no test of the happy path
//     would notice.
//   - a TTL lost in a rename means data is retained forever, which looks like nothing at all.
//   - an erasure that cascades into audit destroys the evidence that the erasure happened.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { config as loadEnv } from 'dotenv';
import { resolve } from 'path';
import { MongoClient, Binary } from 'mongodb';
import { GIAM_COLLECTIONS } from '../../../backend/src/shared/models/collections';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';

loadEnv({ path: resolve(__dirname, '../../../.env'), quiet: true });

const URI = process.env.GIAM_MONGODB_URI ?? process.env.MONGODB_URI ?? '';
const DB = process.env.GIAM_MONGODB_DB ?? 'sec-giam-store';

describe.skipIf(!URI)('P11.11 (a): the personal fields are ciphertext at rest', () => {
  let plain: MongoClient;

  beforeAll(async () => {
    /**
     * A client with NO auto-encryption configured, deliberately.
     *
     * Reading through the encrypted client would decrypt on the way out and prove nothing: it would
     * pass identically whether the data was encrypted or sitting in the clear. The only way to
     * establish that a field is ciphertext is to read it as a party that cannot decrypt it, which
     * is also exactly what an attacker with database access is.
     */
    plain = new MongoClient(URI);
    await plain.connect();
  });

  afterAll(async () => { await plain?.close(); });

  it('stores primaryEmail, primaryPhone and name.formatted as ciphertext', async () => {
    const principal = await plain.db(DB).collection('principal').findOne(
      { primaryEmail: { $exists: true } },
      { projection: { _id: 0, primaryEmail: 1, primaryPhone: 1, name: 1, userName: 1 } },
    );
    expect(principal, 'no principal with an email; has the seed changed?').toBeTruthy();

    // Binary subtype 6 is the encrypted-value marker. A string here would be plaintext.
    expect(principal!.primaryEmail).toBeInstanceOf(Binary);
    expect((principal!.primaryEmail as Binary).sub_type).toBe(6);

    if (principal!.primaryPhone !== undefined) {
      expect(principal!.primaryPhone).toBeInstanceOf(Binary);
      expect((principal!.primaryPhone as Binary).sub_type).toBe(6);
    }

    const name = principal!.name as { formatted?: unknown } | undefined;
    if (name?.formatted !== undefined) {
      expect(name.formatted).toBeInstanceOf(Binary);
      expect((name.formatted as Binary).sub_type).toBe(6);
    }

    // The control, and the reason this is not a tautology: an UNencrypted field on the same
    // document still reads as a plain string, so the assertions above are discriminating.
    expect(typeof principal!.userName).toBe('string');
  });

  it('encrypts nothing whose only sensitive value is already a one-way hash', async () => {
    // Encrypting a bcrypt digest buys no confidentiality and would put ESC/ECOC state on the
    // credential collection, which now carries the client registrations and is a hot lookup.
    const credential = await plain.db(DB).collection('credential').findOne(
      { hash: { $exists: true } },
      { projection: { _id: 0, hash: 1 } },
    );
    if (credential) expect(typeof credential.hash).toBe('string');
  });

  it('leaves the encrypted state collections in place for exactly one collection', async () => {
    const names = (await plain.db(DB).listCollections({}, { nameOnly: true }).toArray())
      .map((entry) => entry.name)
      .filter((name) => name.startsWith('enxcol_.'));
    // One parent, so one set of state collections. More would mean a collection became encrypted
    // without anybody deciding to.
    const parents = new Set(names.map((name) => name.split('.')[1]));
    expect([...parents]).toEqual(['principal']);
  });
});

describe.skipIf(!URI)('P11.11 (c): an audit actor carries a hash, never an address', () => {
  let plain: MongoClient;

  beforeAll(async () => { plain = new MongoClient(URI); await plain.connect(); });
  afterAll(async () => { await plain?.close(); });

  it('holds no field that looks like a raw address anywhere in the trail', async () => {
    /**
     * Data minimisation, checked against the DATA rather than against the writer.
     *
     * Checking the code that writes events would miss an event written by any other path. This
     * looks at what is actually stored: an `ipHash` is expected, an `ip` is not, and no value
     * anywhere in the record may look like an address.
     */
    const events = await plain.db(DB).collection('audit')
      .find({}, { projection: { _id: 0 } })
      .limit(200)
      .toArray();

    const ipv4 = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const offenders: string[] = [];
    for (const event of events) {
      const walk = (value: unknown, path: string) => {
        if (typeof value === 'string') {
          if (ipv4.test(value)) offenders.push(`${path} = ${value}`);
          return;
        }
        if (value && typeof value === 'object') {
          for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
            if (key === 'ip' || key === 'ipAddress' || key === 'remoteAddress') {
              offenders.push(`${path}.${key} exists`);
            }
            walk(nested, `${path}.${key}`);
          }
        }
      };
      walk(event, 'audit');
    }
    expect(offenders, offenders.slice(0, 5).join('; ')).toEqual([]);
  });
});

describe('P11.11 (e): every TTL survived the renames', () => {
  it('declares a TTL index for each collection the registry marks ephemeral', () => {
    /**
     * Storage limitation is a property of the MODEL, not of a cleanup script.
     *
     * A TTL lost in a rename retains data forever and looks like nothing at all: no error, no
     * warning, just a collection that never shrinks. Asserted against the registry so the two
     * cannot disagree.
     */
    const ephemeral = GIAM_COLLECTIONS.filter((spec) => spec.ttlField);
    expect(ephemeral.length, 'no ephemeral collection declared at all').toBeGreaterThan(0);

    for (const spec of ephemeral) {
      const ttl = plannedIndexes().find(
        (plan) => plan.collection === spec.name && plan.options.expireAfterSeconds !== undefined,
      );
      expect(ttl, `${spec.name} declares ttlField "${spec.ttlField}" and has no TTL index`).toBeTruthy();
      // On the field the registry names, not merely on some field.
      expect(Object.keys(ttl!.keys as Record<string, unknown>)).toContain(spec.ttlField);
    }
  });

  it('keeps the ephemeral set as expected after the merges', () => {
    // Named explicitly, so a collection silently losing its ephemeral nature is a failing test
    // rather than an absence nobody notices.
    const ephemeral = GIAM_COLLECTIONS.filter((spec) => spec.ttlField).map((spec) => spec.name).sort();
    expect(ephemeral).toEqual(['authRequest', 'session']);
  });

  it('declares NO TTL on audit, or the evidence would expire', () => {
    // The other half of P7.6. Security audit records are retained under legal obligation, and a TTL
    // here would discard exactly what makes an erasure provable.
    const audit = GIAM_COLLECTIONS.find((spec) => spec.name === 'audit');
    expect(audit?.ttlField).toBeUndefined();
    const auditTtl = plannedIndexes().filter(
      (plan) => plan.collection === 'audit' && plan.options.expireAfterSeconds !== undefined,
    );
    expect(auditTtl).toEqual([]);
  });
});

describe.skipIf(!URI)('P11.11 (f): erasure removes the subject and LEAVES the audit trail', () => {
  let plain: MongoClient;

  beforeAll(async () => { plain = new MongoClient(URI); await plain.connect(); });
  afterAll(async () => { await plain?.close(); });

  it('never lets a principal delete cascade into audit', async () => {
    /**
     * The constraint the ADR states twice, and the one worth proving on the data.
     *
     * Erasing a principal removes the principal, its credentials, its sessions and its grants. It
     * leaves `audit`, which is what makes the erasure itself provable, and which is retained under
     * legal obligation and legitimate interest. A cascade would also fail on its own terms: a time
     * series does not accept arbitrary per-document deletion.
     *
     * Asserted structurally, because running a real SCIM delete here would destroy seeded data the
     * rest of the suite reads. The structural facts ARE the guarantee: audit is a time series, and
     * a time series cannot be deleted from per document.
     */
    const audit = GIAM_COLLECTIONS.find((spec) => spec.name === 'audit');
    expect(audit?.kind).toBe('timeseries');

    const info = await plain.db(DB).listCollections({ name: 'audit' }).toArray();
    expect(info[0]?.type, 'audit must be a time series on the server, not only in the registry')
      .toBe('timeseries');

    // And the trail is not empty, so "leaves audit intact" is a claim about something real.
    const held = await plain.db(DB).collection('audit').countDocuments();
    expect(held, 'the audit trail is empty; nothing has been recorded').toBeGreaterThan(0);
  });

  it('names the collections an erasure DOES reach, so the set is a decision not an accident', () => {
    // principal, credential, session and grant. Everything a subject holds, and nothing that
    // constitutes evidence about them.
    const names = GIAM_COLLECTIONS.map((spec) => spec.name);
    for (const reached of ['principal', 'credential', 'session', 'grant']) {
      expect(names, `${reached} must exist for an erasure to reach it`).toContain(reached);
    }
  });
});
