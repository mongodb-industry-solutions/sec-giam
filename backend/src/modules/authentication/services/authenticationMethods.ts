import { Db } from 'mongodb';
import * as bcrypt from 'bcryptjs';
import type { AuthenticationMethod, PrincipalResolution } from '../../../shared/ports';
import { credentialStores } from '../../../shared/ports';
import { DirectoryService } from '../../directory/services/directory.service';
import { CLIENT_COLLECTION } from '../../../shared/models/collections';
import { ClientRecord } from '../../oauth/models/client.model';
import { canAuthenticate } from '../../directory/models/identity.model';

/**
 * How a principal proves who it is.
 *
 * All three resolve a principal and return the same shape, and everything above them, the token
 * issuance, the audit record, the session, is the same code for all three. That is the one-pipeline
 * rule made concrete: a person signing in with a password, a person approving on a device and a
 * microservice presenting a secret differ HERE and nowhere else.
 *
 * The assurance each one reports is the level it actually achieved, not the level that was asked
 * for. A method that reported what was requested would make the claim worthless.
 */

let boundDb: Db | null = null;

export function bindAuthenticationMethods(db: Db): void {
  boundDb = db;
}

function directory(): DirectoryService {
  if (!boundDb) throw new Error('Authentication methods are not bound to a database');
  return new DirectoryService(boundDb);
}

/**
 * Password.
 *
 * Applies to people only, and that is a statement rather than an oversight: a password policy has no
 * meaning for a workload, and letting one hold a password is how a service account ends up with a
 * credential a person chose and never rotates.
 */
export const passwordMethod: AuthenticationMethod = {
  name: 'password',
  appliesTo: ['human'],
  maxAssurance: 'aal1',

  async authenticate(context): Promise<PrincipalResolution | null> {
    const login = String(context.presented.login ?? '');
    const password = String(context.presented.password ?? '');
    if (!login || !password) return null;

    const service = directory();
    const identity = await service.findByLogin(context.realmId, login);
    // A principal that cannot authenticate is refused before any credential is examined, so a
    // suspended account cannot be probed for a valid password.
    if (!identity || !canAuthenticate(identity)) return null;

    const store = credentialStores.resolve('bcrypt-password');
    for (const credential of await service.credentialsFor(identity.subjectId, 'password')) {
      if (await store.verify(credential.credentialId, password)) {
        return {
          subjectId: identity.subjectId,
          realmId: identity.realmId,
          assuranceLevel: 'aal1',
          method: this.name,
          credentialId: credential.credentialId,
        };
      }
    }
    return null;
  },
};

/**
 * A registered public key, proving possession of a device.
 *
 * Higher assurance than a password because it proves possession of something rather than knowledge
 * of something, and the private half never crosses the wire even once.
 */
export const publicKeyMethod: AuthenticationMethod = {
  name: 'public_key',
  appliesTo: ['human'],
  maxAssurance: 'aal2',

  async authenticate(context): Promise<PrincipalResolution | null> {
    const subjectId = String(context.presented.subjectId ?? '');
    const proof = String(context.presented.proof ?? '');
    if (!subjectId || !proof) return null;

    const service = directory();
    const identity = await service.findBySubjectId(subjectId);
    if (!identity || identity.realmId !== context.realmId || !canAuthenticate(identity)) return null;

    const store = credentialStores.resolve('public-key');
    for (const credential of await service.credentialsFor(subjectId, 'public_key')) {
      if (await store.verify(credential.credentialId, proof)) {
        return {
          subjectId,
          realmId: identity.realmId,
          assuranceLevel: 'aal2',
          method: this.name,
          credentialId: credential.credentialId,
        };
      }
    }
    return null;
  },
};

/**
 * A client secret, for a principal that is not a person.
 *
 * The same pipeline as the two above: it resolves a principal, reports assurance and produces the
 * same shape. What it does NOT do is exist as a parallel implementation, which is the failure this
 * arrangement is built to avoid, because a second pipeline is how one of the two ends up without an
 * audit trail.
 */
export const clientSecretMethod: AuthenticationMethod = {
  name: 'client_secret',
  appliesTo: ['workload', 'application', 'service', 'agent'],
  maxAssurance: 'aal1',

  async authenticate(context): Promise<PrincipalResolution | null> {
    if (!boundDb) throw new Error('Authentication methods are not bound to a database');
    const clientId = String(context.presented.clientId ?? '');
    const clientSecret = String(context.presented.clientSecret ?? '');
    if (!clientId || !clientSecret) return null;

    const client = await boundDb
      .collection<ClientRecord>(CLIENT_COLLECTION)
      .findOne({ realmId: context.realmId, clientId }, { projection: { _id: 0 } });
    if (!client || client.status !== 'active' || !client.clientSecretHash) return null;
    if (!await bcrypt.compare(clientSecret, client.clientSecretHash)) return null;

    // A machine principal is identified by its client id. It is a principal in its own right, with an
    // owner, a lifecycle and an audit trail, rather than an anonymous key.
    return {
      subjectId: clientId,
      realmId: client.realmId,
      assuranceLevel: 'aal1',
      method: this.name,
    };
  },
};
