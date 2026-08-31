import { Meta, Scoped } from '../../../shared/models/base.model';

/**
 * An upstream identity provider, federated inside a realm.
 *
 * This is the half of the platform's old authentication domain that was about PROTOCOL, split away
 * from the half that was about tenancy. Conflating them is why adding a second identity source used
 * to look like adding a second tenant.
 *
 * A realm with no provider row authenticates internally. Adding a third-party provider is this record
 * plus a claim mapping: no application code, no application deployment, no application restart. That
 * is the whole argument for brokering rather than each application implementing OIDC and SAML again.
 */
export interface IdentityProviderRecord extends Scoped {
  providerId: string;
  /** Slug, unique inside the realm. */
  name: string;
  displayName: string;
  protocol: 'internal' | 'oidc' | 'saml' | 'spiffe';
  /** Which port implementation handles it. Configuration on the record, never an environment read. */
  adapter: string;
  enabled: boolean;
  /** Shown when a provider is visible but not yet usable, rather than failing after it is chosen. */
  notice?: string;
  config: {
    issuer?: string;
    clientId?: string;
    clientSecretRef?: string;
    authorizationEndpoint?: string;
    tokenEndpoint?: string;
    jwksUri?: string;
    scopes?: string[];
    tenant?: string;
    /** Home-realm discovery: an entered email domain resolves to this provider. */
    emailDomains?: string[];
    [setting: string]: unknown;
  };
  /**
   * Upstream claim to local role.
   *
   * The mapping is data because the alternative is an application learning what an upstream group is
   * called, which is exactly the coupling brokering removes.
   */
  claimMappings: Array<{ claim: string; value: string; roleName: string }>;
  meta: Meta;
}
