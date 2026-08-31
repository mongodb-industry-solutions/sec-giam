/**
 * The port registry: how GIAM is extended without any calling module changing.
 *
 * Three rules make a port real rather than decorative, and this registry is what enforces them.
 *
 * 1. An implementation is chosen by a NAME that comes from configuration on a realm or a resource
 *    server, never from an environment variable read deep inside a service. Configuration that only
 *    exists as an environment variable cannot vary per tenant, which defeats the point.
 * 2. Adding an implementation requires no change to a calling module: it registers itself by name and
 *    the caller resolves by name. If adding one means editing a switch statement, the port is a
 *    decoration around a switch statement.
 * 3. A capability that is not implemented is ABSENT, not faked. Resolving an unknown name throws a
 *    refusal that says what is missing and what is available, rather than falling back to something
 *    weaker. Silently degrading an authentication method is how a system ends up authenticating
 *    nobody correctly.
 */

export interface PortImplementation {
  /** The name configuration refers to. Stable, because it is written into realm records. */
  readonly name: string;
}

export class PortResolutionError extends Error {
  constructor(public readonly port: string, public readonly requested: string, available: string[]) {
    super(
      `No "${requested}" implementation of the ${port} port. `
      + `Available: ${available.length > 0 ? available.join(', ') : '(none registered)'}. `
      + 'This capability is absent rather than degraded: configure a registered implementation.',
    );
    this.name = 'PortResolutionError';
  }
}

export class PortRegistry<T extends PortImplementation> {
  private readonly implementations = new Map<string, T>();

  constructor(public readonly port: string) {}

  register(implementation: T): this {
    if (this.implementations.has(implementation.name)) {
      // Two implementations answering to one name is a configuration that silently means one of them.
      throw new Error(`Duplicate ${this.port} implementation "${implementation.name}"`);
    }
    this.implementations.set(implementation.name, implementation);
    return this;
  }

  /** Replaces an implementation. Only a test needs this, to swap a real adapter for a fake. */
  override(implementation: T): this {
    this.implementations.set(implementation.name, implementation);
    return this;
  }

  resolve(name: string): T {
    const found = this.implementations.get(name);
    if (!found) throw new PortResolutionError(this.port, name, this.names());
    return found;
  }

  has(name: string): boolean {
    return this.implementations.has(name);
  }

  names(): string[] {
    return [...this.implementations.keys()].sort();
  }

  size(): number {
    return this.implementations.size;
  }

  clear(): void {
    this.implementations.clear();
  }
}

/** Every port GIAM declares. The list is what the day-one invariant test iterates. */
export const PORT_NAMES = [
  'AuthenticationMethod',
  'CredentialStore',
  'IdentityProvider',
  'KeyProvider',
  'PolicyEvaluator',
  'TokenFormat',
  'ProofOfPossession',
  'EventSink',
  'ProvisioningTarget',
] as const;

export type PortName = (typeof PORT_NAMES)[number];
