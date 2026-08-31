import { keyProviders, authenticationMethods, credentialStores, policyEvaluators, identityProviders, provisioningTargets } from './index';
import { InstanceLocalKeyProvider } from '../../modules/keys/providers/instanceLocal.provider';
import { FilesystemKeyProvider } from '../../modules/keys/providers/filesystem.provider';
import { SharedStoreKeyProvider } from '../../modules/keys/providers/sharedStore.provider';
import { KmsKeyProvider } from '../../modules/keys/providers/kms.provider';
import { bcryptPasswordStore, publicKeyStore } from '../../modules/directory/services/credentialStores';
import { passwordMethod, publicKeyMethod, clientSecretMethod } from '../../modules/authentication/services/authenticationMethods';
import { rbacEvaluator, abacEvaluator } from '../../modules/authorization/services/policyEvaluators';
import { oidcIdentityProvider } from '../../modules/realm/services/oidcProvider';
import { webhookProvisioningTarget } from '../../modules/provisioning/services/webhookTarget';

/**
 * Registers the implementations GIAM ships with.
 *
 * Called once at boot, and again by tests that need a clean registry. Nothing here reads an
 * environment variable to decide WHICH implementation to use: it registers all of them by name, and
 * configuration names the one it wants. That is the difference between a port and a switch statement
 * with extra steps.
 *
 * A port with no entry here is declared and not yet delivered, and PORT_DELIVERY records which phase
 * owns it. It is absent rather than faked: resolving it refuses and says what is missing.
 */
export function registerBuiltinPorts(): void {
  // Idempotent PER REGISTRY, because a test may clear one and leave the others alone. Guarding on a
  // single registry would leave the rest registered and then fail on a duplicate name, which reads
  // as a defect in the port under test rather than in the guard.
  if (!keyProviders.has('instance-local')) {
    // All four in every deployment. Which one is used is configuration, and every one of them is
    // multi-replica capable, so scaling is never the reason to change custody.
    keyProviders.register(new InstanceLocalKeyProvider());
    keyProviders.register(new FilesystemKeyProvider());
    keyProviders.register(new SharedStoreKeyProvider());
    keyProviders.register(new KmsKeyProvider());
  }

  // Where credential material lives and how it is verified. Two from the start, because a port only
  // proves itself when something other than the obvious implementation goes through it.
  if (!credentialStores.has('bcrypt-password')) {
    credentialStores.register(bcryptPasswordStore);
    credentialStores.register(publicKeyStore);
  }

  // Where a lifecycle change is sent. A suspension has to reach runtime authorization without
  // waiting for a review cycle, which a short token lifetime alone does not achieve.
  if (!provisioningTargets.has('webhook')) {
    provisioningTargets.register(webhookProvisioningTarget);
  }

  // Where an identity may come from. Adding a third-party provider is a record and a claim mapping,
  // with no application code and no application deployment: that is the whole argument for brokering
  // rather than each application implementing OIDC, and then SAML, again.
  if (!identityProviders.has('oidc')) {
    identityProviders.register(oidcIdentityProvider);
  }

  // How a principal proves identity. A person with a password, a person with a device and a machine
  // with a secret all resolve a principal and return the same shape, through the same pipeline.
  if (!authenticationMethods.has('password')) {
    authenticationMethods.register(passwordMethod);
    authenticationMethods.register(publicKeyMethod);
    authenticationMethods.register(clientSecretMethod);
  }

  // How a decision is reached. Two from the start, and the combination rule is deny-wins, so
  // adding an evaluator can only ever make a result more restrictive.
  if (!policyEvaluators.has('rbac')) {
    policyEvaluators.register(rbacEvaluator);
    policyEvaluators.register(abacEvaluator);
  }
}
