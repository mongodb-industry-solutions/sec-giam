// v39: every variable the service reads is documented, and every variable documented is read.
//
// An undocumented variable is one somebody discovers by reading source, or more often by hitting the
// failure it causes. This whole run lost time to exactly that: the master key had no example file and
// no mention outside a runbook table, so the first symptom was the database refusing to open with an
// error that named a variable nobody had been told to set.
//
// The reverse matters too. A documented variable the code no longer reads is worse than a missing
// one, because somebody sets it, believes it took effect, and it silently does nothing.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const ROOT = resolve(__dirname, '../../../..');
const CONFIG = readFileSync(resolve(ROOT, 'giam/backend/src/config.ts'), 'utf8');
const EXAMPLE = readFileSync(resolve(ROOT, 'giam/backend/env.example'), 'utf8');

/** Every variable the configuration actually reads, by the prefixed name an operator would set. */
function readByConfig(): Set<string> {
  return new Set([...CONFIG.matchAll(/giamEnv\('([A-Z0-9_]+)'/g)].map((match) => `GIAM_${match[1]}`));
}

/** Every variable the example names, whether set or shown commented as an option. */
function documented(): Set<string> {
  return new Set([...EXAMPLE.matchAll(/^#?\s*(GIAM_[A-Z0-9_]+)=/gm)].map((match) => match[1]));
}

describe('v39: the configuration surface is documented, both directions', () => {
  it('reads a meaningful number of variables, so a broken parse cannot pass silently', () => {
    // Guards the test itself. If the config format changed and the pattern stopped matching, both
    // sets would be empty and every assertion below would pass by having nothing to compare.
    expect(readByConfig().size).toBeGreaterThan(20);
    expect(documented().size).toBeGreaterThan(20);
  });

  it('documents every variable the service reads', () => {
    const undocumented = [...readByConfig()].filter((name) => !documented().has(name)).sort();
    expect(
      undocumented,
      `read by config.ts but absent from env.example: ${undocumented.join(', ')}`,
    ).toEqual([]);
  });

  it('reads every variable it documents', () => {
    const read = readByConfig();
    // Two exceptions, and they are named rather than pattern-matched. Both are read somewhere other
    // than the configuration module: the federation secret by the provider adapter, from a variable
    // the provider RECORD names, and the AWS credentials by the driver itself.
    const readElsewhere = new Set(['GIAM_FEDERATION_PARTNERBANK_SECRET']);

    const stale = [...documented()]
      .filter((name) => !read.has(name) && !readElsewhere.has(name))
      .sort();
    expect(
      stale,
      `documented but never read, so setting it would silently do nothing: ${stale.join(', ')}`,
    ).toEqual([]);
  });

  it('leaves every secret blank in the example rather than shipping a value', () => {
    // A default credential in a template is a credential in production, because somebody copies the
    // file and changes only what stops them booting.
    const secrets = ['GIAM_KMS_LOCAL_MASTER_KEY', 'GIAM_ADMIN_TOKEN', 'GIAM_KEY_WRAPPING_KEY'];
    for (const name of secrets) {
      const line = EXAMPLE.split('\n').find((entry) => entry.trim().startsWith(`${name}=`));
      if (!line) continue;
      expect(line.trim(), `${name} ships a value in env.example`).toBe(`${name}=`);
    }
  });

  it('says how to generate the master key, and that it cannot be rotated in place', () => {
    // The two things somebody needs at the moment they hit this, and the second is the one that is
    // expensive to learn later: the data is unreadable without the key it was written under.
    expect(EXAMPLE).toMatch(/randomBytes\(96\)/);
    expect(EXAMPLE).toMatch(/NOT ROTATABLE IN PLACE/);
  });
});
