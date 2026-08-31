// Fake implementations of every GIAM port.
//
// Their job is to prove the seam, not to simulate anything. Each one is registered under a name no
// production configuration uses, exercised through the SAME resolution path a real implementation
// goes through, and asserted on. If a fake cannot be substituted without a caller changing, the port
// is an interface nobody has tested as an abstraction, which is the thing the plan forbids.
import type {
  AuthenticationMethod, CredentialStore, IdentityProviderAdapter, KeyProvider,
  PolicyEvaluator, TokenFormat, ProofOfPossession, EventSink, ProvisioningTarget,
  SecurityEventRecord, PortName,
} from '../../../../giam/backend/src/shared/ports';
import { PORT_REGISTRIES } from '../../../../giam/backend/src/shared/ports';

/** The prefix every fake's name carries, so a real implementation can never be mistaken for one. */
export const FAKE_PREFIX = 'fake-';

export const fakeAuthenticationMethod: AuthenticationMethod = {
  name: `${FAKE_PREFIX}authentication`,
  // Both classes deliberately: a fake that only applies to humans would let a machine-only gap
  // through the very test written to catch it.
  appliesTo: ['human', 'workload', 'agent', 'application', 'service'],
  maxAssurance: 'aal2',
  async authenticate(context) {
    const presented = context.presented.secret;
    if (presented !== 'correct') return null;
    return {
      subjectId: String(context.presented.subjectId ?? 'subject-under-test'),
      realmId: context.realmId,
      assuranceLevel: 'aal2',
      method: this.name,
    };
  },
};

export const fakeCredentialStore: CredentialStore = {
  name: `${FAKE_PREFIX}credential-store`,
  credentialType: 'fake',
  async verify(_credentialId, presented) {
    return presented === 'correct';
  },
  async issue(subjectId, secret) {
    return { subjectId, storedAs: `fake:${secret.length}` };
  },
};

export const fakeIdentityProvider: IdentityProviderAdapter = {
  name: `${FAKE_PREFIX}identity-provider`,
  protocol: 'oidc',
  async authorizationUrl(providerId, state) {
    return `https://upstream.invalid/authorize?provider=${providerId}&state=${state}`;
  },
  async exchange(_providerId, payload) {
    return { sub: payload.code, email: 'someone@upstream.invalid' };
  },
};

export const fakeKeyProvider: KeyProvider = {
  name: `${FAKE_PREFIX}key-provider`,
  multiReplicaCapable: true,
  externalCustody: false,
  async ensureKey(realmId) {
    return `${FAKE_PREFIX}${realmId}-kid`;
  },
  async sign(kid, payload) {
    return Buffer.concat([Buffer.from(`${kid}:`), payload]);
  },
  async publicKeyPem() {
    return '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n';
  },
};

export const fakeAllowEvaluator: PolicyEvaluator = {
  name: `${FAKE_PREFIX}allow`,
  async evaluate() {
    return { effect: 'allow', reason: 'the fake allow evaluator allows everything', source: 'fake' };
  },
};

export const fakeDenyEvaluator: PolicyEvaluator = {
  name: `${FAKE_PREFIX}deny`,
  async evaluate() {
    return { effect: 'deny', reason: 'the fake deny evaluator denies everything', source: 'fake' };
  },
};

export const fakeTokenFormat: TokenFormat = {
  name: `${FAKE_PREFIX}token-format`,
  locallyVerifiable: true,
  async issue(claims, kid) {
    return `${kid}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
  },
  async inspect(token) {
    const [, body] = token.split('.');
    if (!body) return null;
    try {
      return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as Record<string, unknown>;
    } catch {
      return null;
    }
  },
};

export const fakeProofOfPossession: ProofOfPossession = {
  name: `${FAKE_PREFIX}proof-of-possession`,
  confirmationClaim: 'x5t#S256',
  async bind(request) {
    return request.certificateThumbprint ?? null;
  },
  async verify(token, request) {
    const confirmation = (token.cnf as { 'x5t#S256'?: string } | undefined)?.['x5t#S256'];
    return Boolean(confirmation) && confirmation === request.certificateThumbprint;
  },
};

export class FakeEventSink implements EventSink {
  readonly name = `${FAKE_PREFIX}event-sink`;

  readonly received: SecurityEventRecord[] = [];

  async emit(event: SecurityEventRecord): Promise<void> {
    this.received.push(event);
  }
}

export class FakeProvisioningTarget implements ProvisioningTarget {
  readonly name = `${FAKE_PREFIX}provisioning-target`;

  readonly pushed: Array<{ operation: string; subjectId: string }> = [];

  async push(operation: 'create' | 'update' | 'deactivate', subjectId: string): Promise<void> {
    this.pushed.push({ operation, subjectId });
  }
}

/** Registers one fake per port, replacing any same-named entry so a test can run twice. */
export function registerFakes(): { eventSink: FakeEventSink; provisioningTarget: FakeProvisioningTarget } {
  const eventSink = new FakeEventSink();
  const provisioningTarget = new FakeProvisioningTarget();

  PORT_REGISTRIES.AuthenticationMethod.override(fakeAuthenticationMethod);
  PORT_REGISTRIES.CredentialStore.override(fakeCredentialStore);
  PORT_REGISTRIES.IdentityProvider.override(fakeIdentityProvider);
  PORT_REGISTRIES.KeyProvider.override(fakeKeyProvider);
  PORT_REGISTRIES.PolicyEvaluator.override(fakeAllowEvaluator);
  PORT_REGISTRIES.PolicyEvaluator.override(fakeDenyEvaluator);
  PORT_REGISTRIES.TokenFormat.override(fakeTokenFormat);
  PORT_REGISTRIES.ProofOfPossession.override(fakeProofOfPossession);
  PORT_REGISTRIES.EventSink.override(eventSink);
  PORT_REGISTRIES.ProvisioningTarget.override(provisioningTarget);

  return { eventSink, provisioningTarget };
}

export function fakeNameFor(port: PortName): string {
  const names = PORT_REGISTRIES[port].names().filter((name) => name.startsWith(FAKE_PREFIX));
  return names[0];
}
