// v40 P3: the field-path map between an OAuth client and the credential that stores it.
//
// This suite exists because a MongoDB field path is a STRING and TypeScript checks none of it. A
// filter naming `clientName` against a collection that stores `metadata.clientName` compiles,
// typechecks, runs, and quietly matches nothing, which reads exactly like a client that does not
// exist. Every path is asserted here rather than trusted, and an unmapped field throws rather than
// passing through to become a query that silently returns empty.
import { describe, it, expect } from 'vitest';
import {
  credentialPath, clientFilter, clientUpdate,
} from '../../../backend/src/modules/oauth/services/clientRegistry';

describe('v40 P3: a client field maps to exactly one credential path', () => {
  it('keeps the identifiers and the lifecycle first class', () => {
    for (const field of ['realmId', 'tenantId', 'clientId', 'status', 'credentialId', 'ownerSubjectId']) {
      expect(credentialPath(field), field).toBe(field);
    }
  });

  it('renames the fields the credential already had its own name for', () => {
    expect(credentialPath('clientSecretHash')).toBe('secretHash');
    expect(credentialPath('clientSecretPrefix')).toBe('secretPrefix');
    // Who may administer the registration, which is NOT the principal it acts as.
    expect(credentialPath('owners')).toBe('administrators');
  });

  it('puts the registration metadata under the metadata sub document', () => {
    expect(credentialPath('clientName')).toBe('metadata.clientName');
    expect(credentialPath('redirectUris')).toBe('metadata.redirectUris');
    expect(credentialPath('grantTypes')).toBe('metadata.grantTypes');
    expect(credentialPath('requirePkce')).toBe('metadata.requirePkce');
    expect(credentialPath('mtls')).toBe('metadata.mtls');
  });

  it('refuses a field it has no path for, rather than inventing one', () => {
    // The whole point. A typo or a field nobody declared must fail loudly at the call site instead
    // of becoming a predicate that matches nothing.
    expect(credentialPath('notAField')).toBeNull();
    expect(() => clientFilter({ notAField: 1 })).toThrow(/no credential path/);
  });
});

describe('v40 P3: a translated filter always narrows to an OAuth client', () => {
  it('adds the type discriminator, so a password cannot answer a client lookup', () => {
    // credential holds passwords, API keys and client registrations together. Without this a client
    // lookup by realm would happily return somebody's password credential.
    expect(clientFilter({ realmId: 'r1' })).toEqual({ realmId: 'r1', type: 'oauth_client' });
  });

  it('translates inside $or, $and and $nor rather than only at the top level', () => {
    // A translation that stopped at the top level would leave the nested halves pointing at paths
    // that do not exist, and the query would still run.
    expect(clientFilter({
      realmId: 'r1',
      $or: [{ clientName: 'a' }, { clientId: 'b' }],
    })).toEqual({
      realmId: 'r1',
      $or: [{ 'metadata.clientName': 'a' }, { clientId: 'b' }],
      type: 'oauth_client',
    });

    expect(clientFilter({ $nor: [{ owners: { $elemMatch: { ref: 'x' } } }] })).toEqual({
      $nor: [{ administrators: { $elemMatch: { ref: 'x' } } }],
      type: 'oauth_client',
    });
  });

  it('carries the operator through untouched, translating only the field name', () => {
    expect(clientFilter({ status: { $ne: 'revoked' } })).toEqual({
      status: { $ne: 'revoked' },
      type: 'oauth_client',
    });
  });
});

describe('v40 P3: an update converts the value where the shape differs', () => {
  it('splits the space-delimited scope into the stored array', () => {
    // RFC 7591 says space-delimited on the wire; an array is what a query can reason about. The
    // conversion lives with the path so the two representations cannot drift apart.
    expect(clientUpdate({ scope: 'openid profile payments.read' }))
      .toEqual({ 'metadata.scopes': ['openid', 'profile', 'payments.read'] });
    expect(clientUpdate({ scope: '' })).toEqual({ 'metadata.scopes': [] });
  });

  it('translates the metadata fields an edit touches', () => {
    expect(clientUpdate({ clientName: 'Orders', logoUri: 'https://x/y.png' })).toEqual({
      'metadata.clientName': 'Orders',
      'metadata.logoUri': 'https://x/y.png',
    });
  });

  it('refuses an unmapped field in an update too', () => {
    expect(() => clientUpdate({ nonsense: true })).toThrow(/no credential path/);
  });
});
