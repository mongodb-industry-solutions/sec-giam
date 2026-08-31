import { PortImplementation, PortRegistry, PORT_NAMES, PortName } from './registry';
import { Scoped } from '../models/base.model';

export * from './registry';

/**
 * The nine extension points, declared in one place.
 *
 * Their shapes are deliberately small and free of any consumer's vocabulary. What differs between a
 * person signing in and a workload presenting a credential is which AuthenticationMethod resolves the
 * principal, not which pipeline runs: authentication resolves a principal, authorisation evaluates
 * permissions, a token is issued, an event is recorded, and the same code does all four for both. A
 * second pipeline for machines is the failure mode these interfaces exist to prevent, because it is
 * how the two halves drift and how one of them ends up without an audit trail.
 */

/** Who is acting, and how sure are we. NIST SP 800-63 assurance travels with the answer. */
export interface PrincipalResolution {
  subjectId: string;
  realmId: string;
  /** The assurance the method actually achieved, not the one that was requested. */
  assuranceLevel: 'aal1' | 'aal2' | 'aal3';
  /** How the principal proved it, recorded so the audit trail can say. */
  method: string;
  credentialId?: string;
}

export interface AuthenticationContext extends Scoped {
  /** Free-form, because what a method needs differs: a password, an assertion, a certificate. */
  presented: Record<string, unknown>;
  clientId?: string;
  /** Hashed before it reaches here: an audit record holds no raw address. */
  ipHash?: string;
}

/** How a principal proves identity. The only thing that differs between a person and a machine. */
export interface AuthenticationMethod extends PortImplementation {
  /** Which principal kinds this method applies to. A password policy does not apply to a workload. */
  readonly appliesTo: ReadonlyArray<'human' | 'workload' | 'agent' | 'application' | 'service'>;
  readonly maxAssurance: PrincipalResolution['assuranceLevel'];
  authenticate(context: AuthenticationContext): Promise<PrincipalResolution | null>;
}

/** Where credential material lives and how it is verified. Never how it is displayed. */
export interface CredentialStore extends PortImplementation {
  /** The credential type this store owns, matching `credential.type`. */
  readonly credentialType: string;
  verify(credentialId: string, presented: string): Promise<boolean>;
  /** Returns the material to persist. A store that cannot mint returns null and says so. */
  issue(subjectId: string, secret: string): Promise<Record<string, unknown> | null>;
}

/** Upstream federation. A realm with no provider authenticates internally. */
export interface IdentityProviderAdapter extends PortImplementation {
  readonly protocol: 'internal' | 'oidc' | 'saml' | 'spiffe';
  /** The URL to send the browser to, or null when the protocol has no redirect step. */
  authorizationUrl(providerId: string, state: string): Promise<string | null>;
  /** Turns whatever came back into claims. Mapping to a role happens above this line. */
  exchange(providerId: string, payload: Record<string, unknown>): Promise<Record<string, unknown>>;
}

/** Signing key custody and rotation. The private key never crosses this interface. */
export interface KeyProvider extends PortImplementation {
  /** True when every replica can verify what any replica signed. All four modes must satisfy it. */
  readonly multiReplicaCapable: boolean;
  /** True when the private key is held outside this process. */
  readonly externalCustody: boolean;
  /** Ensures this instance has a usable signing key in the realm, and returns its kid. */
  ensureKey(realmId: string): Promise<string>;
  sign(kid: string, payload: Buffer): Promise<Buffer>;
  /** The public material to publish for a kid. Public only: this is what a verifier receives. */
  publicKeyPem(kid: string): Promise<string>;
}

export interface AuthorizationRequest extends Scoped {
  subjectId: string;
  resource: string;
  action: string;
  /** Identity context only: time, network, assurance, tenant, ownership, attestation state. */
  context: Record<string, unknown>;
}

export interface AuthorizationDecision {
  effect: 'allow' | 'deny';
  /** Why, in terms a log can carry. A decision with no reason is not auditable. */
  reason: string;
  /** The policy or role that decided, so an operator can find it. */
  source?: string;
}

/** How a decision is reached. Deny always wins across evaluators. */
export interface PolicyEvaluator extends PortImplementation {
  evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision | null>;
}

/** How an access token is represented on the wire. */
export interface TokenFormat extends PortImplementation {
  /** True when a resource server can verify it without calling GIAM. */
  readonly locallyVerifiable: boolean;
  issue(claims: Record<string, unknown>, kid: string): Promise<string>;
  /** Returns the claims, or null when the token is not this format's to read. */
  inspect(token: string): Promise<Record<string, unknown> | null>;
}

/** Sender constraint. Bearer is the floor, not the target. */
export interface ProofOfPossession extends PortImplementation {
  /** What binds the token to its holder, recorded in the token so a verifier can check it. */
  readonly confirmationClaim: string | null;
  /** Binding material derived from the request, or null when this mode binds nothing. */
  bind(request: { headers: Record<string, unknown>; certificateThumbprint?: string }): Promise<string | null>;
  verify(token: Record<string, unknown>, request: { headers: Record<string, unknown>; certificateThumbprint?: string }): Promise<boolean>;
}

export interface SecurityEventRecord extends Scoped {
  ts: string;
  action: string;
  outcome: 'success' | 'failure';
  correlationId?: string;
  [key: string]: unknown;
}

/** Where security events go. More than one sink may be active; none of them may swallow an event. */
export interface EventSink extends PortImplementation {
  emit(event: SecurityEventRecord): Promise<void>;
}

/** Outbound identity lifecycle. Provisioning creates a principal; it never activates one. */
export interface ProvisioningTarget extends PortImplementation {
  push(operation: 'create' | 'update' | 'deactivate', subjectId: string, payload: Record<string, unknown>): Promise<void>;
}

export const authenticationMethods = new PortRegistry<AuthenticationMethod>('AuthenticationMethod');
export const credentialStores = new PortRegistry<CredentialStore>('CredentialStore');
export const identityProviders = new PortRegistry<IdentityProviderAdapter>('IdentityProvider');
export const keyProviders = new PortRegistry<KeyProvider>('KeyProvider');
export const policyEvaluators = new PortRegistry<PolicyEvaluator>('PolicyEvaluator');
export const tokenFormats = new PortRegistry<TokenFormat>('TokenFormat');
export const proofOfPossessionModes = new PortRegistry<ProofOfPossession>('ProofOfPossession');
export const eventSinks = new PortRegistry<EventSink>('EventSink');
export const provisioningTargets = new PortRegistry<ProvisioningTarget>('ProvisioningTarget');

/** Every registry, by port name, so the invariant test can iterate them without naming each one. */
export const PORT_REGISTRIES: Record<PortName, PortRegistry<PortImplementation>> = {
  AuthenticationMethod: authenticationMethods as PortRegistry<PortImplementation>,
  CredentialStore: credentialStores as PortRegistry<PortImplementation>,
  IdentityProvider: identityProviders as PortRegistry<PortImplementation>,
  KeyProvider: keyProviders as PortRegistry<PortImplementation>,
  PolicyEvaluator: policyEvaluators as PortRegistry<PortImplementation>,
  TokenFormat: tokenFormats as PortRegistry<PortImplementation>,
  ProofOfPossession: proofOfPossessionModes as PortRegistry<PortImplementation>,
  EventSink: eventSinks as PortRegistry<PortImplementation>,
  ProvisioningTarget: provisioningTargets as PortRegistry<PortImplementation>,
};

/**
 * Which phase delivers each port's first real implementation.
 *
 * Recorded so "declared but not yet implemented" is a stated position with an owner rather than an
 * omission somebody discovers. The invariant test reads this: a port past its phase with no real
 * implementation fails, and a port before its phase is allowed to have only the test fake.
 */
export const PORT_DELIVERY: Record<PortName, string> = {
  KeyProvider: 'P0',
  AuthenticationMethod: 'P5',
  CredentialStore: 'P5',
  IdentityProvider: 'P5',
  TokenFormat: 'P5',
  PolicyEvaluator: 'P8',
  EventSink: 'P8',
  ProofOfPossession: 'P8',
  ProvisioningTarget: 'P10',
};

export { PORT_NAMES };
export type { PortName };
