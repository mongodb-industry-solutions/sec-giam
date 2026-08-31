// v39 P0.5: the extension points, proven as abstractions rather than declared as interfaces.
//
// The plan's rule is that a port with one implementation is an interface nobody has tested as an
// abstraction. These tests are what makes that rule mechanical: every port resolves by a name that
// comes from configuration, a fake substitutes for a real implementation through the same path, and
// an unknown name is refused rather than quietly degraded.
import { describe, it, expect, beforeEach } from 'vitest';
import {
  PORT_NAMES, PORT_REGISTRIES, PORT_DELIVERY, PortResolutionError,
  authenticationMethods, credentialStores, identityProviders, keyProviders,
  policyEvaluators, tokenFormats, proofOfPossessionModes, eventSinks, provisioningTargets,
  type PortName,
} from '../../../../giam/backend/src/shared/ports';
import { registerBuiltinPorts } from '../../../../giam/backend/src/shared/ports/builtins';
import { registerFakes, FAKE_PREFIX, fakeAllowEvaluator, fakeDenyEvaluator } from '../support/portFakes';

/**
 * The phases whose real implementations have landed.
 *
 * A port whose delivering phase is in this set must carry at least TWO real implementations, which is
 * the plan's actual rule: an abstraction with one implementation has never been tested as one. A port
 * due later carries only the fake, and the fake still has to prove the seam, which is what the second
 * block of tests does. Each phase adds its own entry here as it lands.
 */
const DELIVERED_PHASES = new Set<string>(['P0']);

let fakes: ReturnType<typeof registerFakes>;

beforeEach(() => {
  for (const port of PORT_NAMES) PORT_REGISTRIES[port].clear();
  registerBuiltinPorts();
  fakes = registerFakes();
});

describe('v39 P0.5: every port is a proven seam', () => {
  it('declares a registry for every port name, and no orphan registry', () => {
    expect(Object.keys(PORT_REGISTRIES).sort()).toEqual([...PORT_NAMES].sort());
  });

  it('gives every port a substitutable implementation, so the seam is exercised from day one', () => {
    for (const port of PORT_NAMES) {
      expect(PORT_REGISTRIES[port].size(), `${port} has no implementation at all`).toBeGreaterThan(0);
    }
  });

  it('gives every delivered port at least two real implementations', () => {
    for (const port of PORT_NAMES) {
      if (!DELIVERED_PHASES.has(PORT_DELIVERY[port])) continue;
      const real = PORT_REGISTRIES[port].names().filter((name) => !name.startsWith(FAKE_PREFIX));
      expect(
        real.length,
        `${port} was delivered in ${PORT_DELIVERY[port]} with ${real.length} real implementation(s): `
        + 'an abstraction with one implementation has never been tested as one',
      ).toBeGreaterThanOrEqual(2);
    }
  });

  it('records a delivering phase for every port, so "not yet" is a position and not an omission', () => {
    for (const port of PORT_NAMES) {
      expect(PORT_DELIVERY[port as PortName], `${port} has no delivering phase`).toMatch(/^P\d+$/);
    }
  });

  it('refuses an unknown implementation instead of degrading to a weaker one', () => {
    for (const port of PORT_NAMES) {
      let thrown: unknown;
      try {
        PORT_REGISTRIES[port].resolve('no-such-implementation');
      } catch (err) {
        thrown = err;
      }
      expect(thrown, `${port} did not refuse an unknown name`).toBeInstanceOf(PortResolutionError);
      // The refusal has to name what is missing and what exists, or an operator cannot act on it.
      expect((thrown as Error).message).toContain(port);
      expect((thrown as Error).message).toContain('no-such-implementation');
    }
  });

  it('refuses to register two implementations under one name', () => {
    expect(() => policyEvaluators.register(fakeAllowEvaluator)).toThrow(/Duplicate/);
  });
});

describe('v39 P0.5: each seam is exercised through the fake', () => {
  it('AuthenticationMethod resolves a principal, and refuses when the proof is wrong', async () => {
    const method = authenticationMethods.resolve(`${FAKE_PREFIX}authentication`);
    const context = { realmId: 'r1', tenantId: 'default', presented: { secret: 'correct', subjectId: 's1' } };
    await expect(method.authenticate(context)).resolves.toMatchObject({ subjectId: 's1', assuranceLevel: 'aal2' });
    await expect(method.authenticate({ ...context, presented: { secret: 'wrong' } })).resolves.toBeNull();
  });

  it('AuthenticationMethod applies to non-human principals too, not only to people', () => {
    // A method that only ever applies to humans is the first symptom of a second pipeline for
    // machines, which is the failure the one-pipeline rule exists to prevent.
    const method = authenticationMethods.resolve(`${FAKE_PREFIX}authentication`);
    expect(method.appliesTo).toContain('workload');
    expect(method.appliesTo).toContain('agent');
  });

  it('CredentialStore verifies and issues without the caller knowing the material', async () => {
    const store = credentialStores.resolve(`${FAKE_PREFIX}credential-store`);
    await expect(store.verify('c1', 'correct')).resolves.toBe(true);
    await expect(store.verify('c1', 'wrong')).resolves.toBe(false);
    await expect(store.issue('s1', 'secret')).resolves.toMatchObject({ subjectId: 's1' });
  });

  it('IdentityProvider produces a redirect and turns a callback into claims', async () => {
    const provider = identityProviders.resolve(`${FAKE_PREFIX}identity-provider`);
    await expect(provider.authorizationUrl('p1', 'state-1')).resolves.toContain('state=state-1');
    await expect(provider.exchange('p1', { code: 'abc' })).resolves.toMatchObject({ sub: 'abc' });
  });

  it('KeyProvider signs and publishes public material only', async () => {
    const provider = keyProviders.resolve(`${FAKE_PREFIX}key-provider`);
    const kid = await provider.ensureKey('r1');
    await expect(provider.sign(kid, Buffer.from('payload'))).resolves.toBeInstanceOf(Buffer);
    const pem = await provider.publicKeyPem(kid);
    // What crosses this interface is public. A private PEM here would be the compromise the whole
    // key-custody design exists to prevent.
    expect(pem).toContain('PUBLIC KEY');
    expect(pem).not.toContain('PRIVATE KEY');
  });

  it('PolicyEvaluator supports more than one evaluator, and deny wins across them', async () => {
    const request = { realmId: 'r1', tenantId: 'default', subjectId: 's1', resource: 'x', action: 'view', context: {} };
    const decisions = await Promise.all(
      [fakeAllowEvaluator, fakeDenyEvaluator].map((e) => policyEvaluators.resolve(e.name).evaluate(request)),
    );
    expect(decisions.some((d) => d?.effect === 'deny')).toBe(true);
    // Every decision carries a reason: a decision a log cannot explain is not auditable.
    for (const decision of decisions) expect(decision?.reason).toBeTruthy();
  });

  it('TokenFormat round-trips claims and reports whether it can be verified locally', async () => {
    const format = tokenFormats.resolve(`${FAKE_PREFIX}token-format`);
    const token = await format.issue({ sub: 's1', aud: 'leafypay' }, 'kid-1');
    await expect(format.inspect(token)).resolves.toMatchObject({ sub: 's1' });
    await expect(format.inspect('not-a-token')).resolves.toBeNull();
    expect(typeof format.locallyVerifiable).toBe('boolean');
  });

  it('ProofOfPossession binds a token to its holder and refuses a mismatch', async () => {
    const mode = proofOfPossessionModes.resolve(`${FAKE_PREFIX}proof-of-possession`);
    const thumbprint = await mode.bind({ headers: {}, certificateThumbprint: 'abc' });
    expect(thumbprint).toBe('abc');
    const token = { cnf: { 'x5t#S256': 'abc' } };
    await expect(mode.verify(token, { headers: {}, certificateThumbprint: 'abc' })).resolves.toBe(true);
    // A stolen bearer token presented from elsewhere is exactly what this refusal is for.
    await expect(mode.verify(token, { headers: {}, certificateThumbprint: 'other' })).resolves.toBe(false);
  });

  it('EventSink receives what is emitted, so no event is silently swallowed', async () => {
    const sink = eventSinks.resolve(fakes.eventSink.name);
    await sink.emit({
      realmId: 'r1', tenantId: 'default', ts: new Date().toISOString(),
      action: 'authentication.succeeded', outcome: 'success',
    });
    expect(fakes.eventSink.received).toHaveLength(1);
    expect(fakes.eventSink.received[0].action).toBe('authentication.succeeded');
  });

  it('ProvisioningTarget pushes a lifecycle change without activating anything', async () => {
    const target = provisioningTargets.resolve(fakes.provisioningTarget.name);
    await target.push('create', 's1', {});
    expect(fakes.provisioningTarget.pushed).toEqual([{ operation: 'create', subjectId: 's1' }]);
  });
});
