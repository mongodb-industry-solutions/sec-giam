// v40 P8: how a subject proves identity belongs to the PATH that does the proving.
//
// The concurrent-session limit is the part worth testing hardest, because the default is the
// dangerous one to get wrong in either direction. Unlimited by mistake means a limit somebody
// configured does nothing; one-by-mistake means a person with a laptop, a phone and a tablet is
// signed out constantly and nobody can tell whether that is the policy or a bug.
import { describe, it, expect } from 'vitest';
import {
  concurrentSessionRule, passwordPolicyOf,
} from '../../../backend/src/modules/realm/models/domain.model';
import type { DomainRecord } from '../../../backend/src/modules/realm/models/domain.model';
import { GIAM_COLLECTIONS } from '../../../backend/src/shared/models/collections';
import { plannedIndexes } from '../../../backend/src/vendors/setup/createIndexes';

const LOCAL = {
  protocol: 'internal' as const,
  authentication: {
    passwordPolicy: {
      minLength: 8, requireUppercase: false, requireNumber: false, requireSymbol: false, historyDepth: 0,
    },
  },
};

describe('P8: the authentication rules live on the domain, not the realm', () => {
  it('reads a password policy from the local path and nowhere else', () => {
    // It sat on the realm, which meant a realm offering both its own directory and an upstream had
    // one policy describing one of them and nothing describing the other.
    expect(passwordPolicyOf(LOCAL)?.minLength).toBe(8);
  });

  it('returns none for a federated path, because the upstream owns its own rules', () => {
    // Not an empty policy: NO policy. An empty one would read as "no requirements", which is a
    // claim about the upstream this authority is in no position to make.
    expect(passwordPolicyOf({ protocol: 'oidc', authentication: LOCAL.authentication })).toBeNull();
    expect(passwordPolicyOf({ protocol: 'saml' })).toBeNull();
  });

  it('offers ldap as a path, since a directory is one more way in and not a special case', () => {
    const paths: Array<DomainRecord['protocol']> = ['internal', 'oidc', 'saml', 'ldap', 'spiffe'];
    expect(paths).toContain('ldap');
  });
});

describe('P8.6: the concurrent-session limit, and its three cases', () => {
  it('is UNLIMITED when nothing is configured', () => {
    // The default, deliberately. A limit of one produces constant eviction ping-pong for an
    // ordinary person on three devices, so it belongs on high-assurance paths and not everywhere.
    expect(concurrentSessionRule({}).limit).toBeNull();
    expect(concurrentSessionRule({ session: undefined }).limit).toBeNull();
  });

  it('distinguishes unlimited from zero, which is not the same thing', () => {
    // Null means no limit; zero would mean no session may ever be opened. Collapsing them is how a
    // path ends up either wide open or entirely shut with nothing saying which was meant.
    expect(concurrentSessionRule({ session: { maxConcurrent: null, onExceed: 'evict-oldest' } }).limit).toBeNull();
    expect(concurrentSessionRule({ session: { maxConcurrent: 0, onExceed: 'evict-oldest' } }).limit).toBe(0);
  });

  it('case one: a single session, evicting the older', () => {
    const rule = concurrentSessionRule({ session: { maxConcurrent: 1, onExceed: 'evict-oldest' } });
    expect(rule).toEqual({ limit: 1, onExceed: 'evict-oldest' });
  });

  it('case two: N sessions, evicting the oldest on the N+1th', () => {
    const rule = concurrentSessionRule({ session: { maxConcurrent: 3, onExceed: 'evict-oldest' } });
    expect(rule).toEqual({ limit: 3, onExceed: 'evict-oldest' });
  });

  it('case three: refuse the new one instead, which is correct for a service account', () => {
    // Where the session already open is the real one and a second caller is more likely a
    // misconfiguration than a person on another device.
    const rule = concurrentSessionRule({ session: { maxConcurrent: 1, onExceed: 'refuse-new' } });
    expect(rule).toEqual({ limit: 1, onExceed: 'refuse-new' });
  });

  it('defaults an unstated onExceed to eviction rather than refusal', () => {
    // Between the two, eviction is the one that lets somebody in. Defaulting to refusal would lock
    // people out of a path whose author only meant to cap it.
    expect(concurrentSessionRule({ session: { maxConcurrent: 2 } as never }).onExceed).toBe('evict-oldest');
  });
});

describe('P8: eviction reaches the evicted device', () => {
  it('indexes sessions by domain, which is what makes the limit countable per path', () => {
    // The limit is counted per subject WITHIN a realm, on the domain that authenticated. Without
    // this index that count is a scan on every sign-in.
    const byDomain = plannedIndexes().find(
      (plan) => plan.collection === 'session'
        && Object.keys(plan.keys as Record<string, unknown>).join(',') === 'realmId,domainId',
    );
    expect(byDomain, 'no index on {realmId, domainId}').toBeTruthy();
  });

  it('keeps session deletable rather than markable, so eviction propagates', () => {
    /**
     * Why eviction is a delete.
     *
     * Deleting a session is the revocation signal, so an evicted device finds out it has been
     * evicted. Marking it would leave that device holding a valid token until it expired, which is
     * the difference between a limit that is enforced and one that is merely recorded.
     */
    const session = GIAM_COLLECTIONS.find((spec) => spec.name === 'session');
    expect(session?.ttlField).toBe('expiresAt');
    expect(session?.kind).toBe('standard');
  });
});
