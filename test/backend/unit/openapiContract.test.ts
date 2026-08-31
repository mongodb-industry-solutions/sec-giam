// v39 P0.4: the API document is a deliverable, and the bar is mechanical rather than a review habit.
//
// Every rule here exists because the alternative is a reviewer noticing. An undocumented route, an
// operation with no error shape, a route that is public because nobody said otherwise: each of those
// is invisible in a diff and obvious in a test.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  buildOpenApiApp, isContractRoute, toOpenApiPath, DOCUMENTED_METHODS,
  type OpenApiDocument, type OpenApiOperation, type RegisteredRoute,
} from '../../../../giam/backend/src/shared/services/openapi';

/**
 * Routes that are public by decision, not by omission.
 *
 * A route with no `security` entry has to be provably public, and this list is the proof. Adding to
 * it is a deliberate act that shows up in review; leaving `security` off a new protected route does
 * not, which is exactly the asymmetry the list corrects.
 */
const PROVABLY_PUBLIC = new Set([
  'get /',
  'get /health',
  'get /api/v1/system/health',

  // Public BY SPECIFICATION. Discovery names endpoints and the key set contains public keys whose
  // entire purpose is to be held by anyone verifying a signature. Requiring a credential to read
  // either would break every conforming client and protect nothing.
  'get /realms/{realm}/.well-known/openid-configuration',
  'get /realms/{realm}/.well-known/oauth-authorization-server',
  'get /realms/{realm}/protocol/openid-connect/certs',

  // Public by nature: it is where a credential is presented, so it cannot require one first.
  'post /realms/{realm}/login',

  // Public because a session is the credential, and the session id is in the body. A client
  // secret here would exclude the public clients this endpoint exists to serve.
  'post /realms/{realm}/protocol/openid-connect/auth',

  // Public because a session identifier is the thing being surrendered. Requiring a credential to
  // END a session would leave a session alive whenever the credential was the problem.
  'post /realms/{realm}/protocol/openid-connect/logout',

  // The two halves of a federated sign-in, public for the same reason the local one is. Starting the
  // flow is the first step for somebody who has nothing to present yet, and completing it presents
  // the upstream code, which IS the credential being offered. The code is verified against the
  // provider's published keys before any claim in it is believed.
  'get /realms/{realm}/federation/{provider}/start',
  'post /realms/{realm}/federation/{provider}/callback',

  // Public by nature, like the login route above it: somebody who has no account cannot present one
  // in order to make one. The realm decides whether the route does anything at all, and whether the
  // principal it creates may sign in yet.
  'post /realms/{realm}/register',

  // Public because it is what an unauthenticated visitor is about to be shown. It carries branding,
  // the providers a person may choose and, where a realm declares them, its demo personas: nothing a
  // sign-in page does not already display.
  'get /realms/{realm}/login-context',

  // The device-facing half of backchannel authentication. Holding the request identifier lets a
  // device see what it would be signing and act on it, and every one of these still requires a
  // signature from a registered private key: the identifier alone approves nothing and denies
  // nothing. Requiring a credential here would mean the approving device had to hold one, which is
  // the assumption the flow exists to remove.
  'get /realms/{realm}/protocol/openid-connect/ext/ciba/auth/{authReqId}',
  'post /realms/{realm}/protocol/openid-connect/ext/ciba/auth/{authReqId}/approve',
  'post /realms/{realm}/protocol/openid-connect/ext/ciba/auth/{authReqId}/deny',
]);

let app: FastifyInstance;
let document: OpenApiDocument;
let routes: RegisteredRoute[];

function operations(): Array<{ path: string; method: string; operation: OpenApiOperation }> {
  const found: Array<{ path: string; method: string; operation: OpenApiOperation }> = [];
  for (const [path, item] of Object.entries(document.paths ?? {})) {
    for (const method of DOCUMENTED_METHODS) {
      const operation = (item as Record<string, OpenApiOperation>)[method];
      if (operation) found.push({ path, method, operation });
    }
  }
  return found;
}

beforeAll(async () => {
  ({ app, document, routes } = await buildOpenApiApp());
});

afterAll(async () => {
  await app?.close();
});

describe('v39 P0.4: OpenAPI is the contract, enforced in CI', () => {
  it('is an OpenAPI 3.1 document', () => {
    expect(document.openapi).toMatch(/^3\.1\./);
    expect(document.info.title).toBeTruthy();
    expect(document.info.version).toBeTruthy();
  });

  it('documents every route the server actually serves', () => {
    const documented = new Set(
      operations().map(({ path, method }) => `${method} ${path}`),
    );
    const missing = routes
      .filter(isContractRoute)
      .map((route) => `${route.method.toLowerCase()} ${toOpenApiPath(route.url)}`)
      .filter((key) => !documented.has(key));

    // An endpoint absent from the document is an endpoint nobody agreed to, which is the same
    // mechanical rule the collection registry applies to ownership.
    expect(missing, `undocumented route(s): ${missing.join(', ')}`).toEqual([]);
  });

  it('documents no route the server does not serve', () => {
    const served = new Set(
      routes.filter(isContractRoute).map((r) => `${r.method.toLowerCase()} ${toOpenApiPath(r.url)}`),
    );
    const phantom = operations()
      .map(({ path, method }) => `${method} ${path}`)
      .filter((key) => !served.has(key));
    expect(phantom, `documented but not served: ${phantom.join(', ')}`).toEqual([]);
  });

  it('gives every operation an operationId, a summary, a description and a tag', () => {
    for (const { path, method, operation } of operations()) {
      const where = `${method.toUpperCase()} ${path}`;
      expect(operation.operationId, `${where} has no operationId`).toBeTruthy();
      expect(operation.summary, `${where} has no summary`).toBeTruthy();
      expect(operation.description, `${where} has no description`).toBeTruthy();
      expect(operation.tags?.length, `${where} has no tag`).toBeGreaterThan(0);
    }
  });

  it('keeps operationIds unique, so a generated client has no name collision', () => {
    const ids = operations().map((o) => o.operation.operationId);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('uses only tags the document declares', () => {
    const declared = new Set((document.tags ?? []).map((t) => t.name));
    for (const { path, method, operation } of operations()) {
      for (const tag of operation.tags ?? []) {
        expect(declared.has(tag), `${method.toUpperCase()} ${path} uses undeclared tag "${tag}"`).toBe(true);
      }
    }
  });

  it('states, per operation, which specification it implements or that none applies', () => {
    // The absence of a standard has to be a recorded decision. Otherwise a bespoke endpoint and a
    // conforming one read identically, and only the author knows which is which.
    const cites = /RFC\s?\d{4}|SCIM|OpenID|OIDC|IETF|NIST|SPIFFE|AuthZEN|Berlin Group|no applicable standard/i;
    for (const { path, method, operation } of operations()) {
      expect(
        cites.test(operation.description ?? ''),
        `${method.toUpperCase()} ${path} names neither a specification nor "no applicable standard"`,
      ).toBe(true);
    }
  });

  it('describes every response it declares', () => {
    for (const { path, method, operation } of operations()) {
      const responses = Object.entries(operation.responses ?? {});
      expect(responses.length, `${method.toUpperCase()} ${path} declares no response`).toBeGreaterThan(0);
      for (const [status, response] of responses) {
        expect(
          response.description,
          `${method.toUpperCase()} ${path} response ${status} has no description`,
        ).toBeTruthy();
      }
    }
  });

  it('carries at least one response example wherever it returns content', () => {
    for (const { path, method, operation } of operations()) {
      const contents = Object.values(operation.responses ?? {})
        .flatMap((response) => Object.values(response.content ?? {}));
      if (contents.length === 0) continue;
      const hasExample = contents.some((media) => {
        const schema = media.schema as { example?: unknown; examples?: unknown } | undefined;
        return media.example !== undefined || media.examples !== undefined
          || schema?.example !== undefined || schema?.examples !== undefined;
      });
      expect(hasExample, `${method.toUpperCase()} ${path} returns content with no example`).toBe(true);
    }
  });

  it('documents an authentication failure on every protected operation', () => {
    for (const { path, method, operation } of operations()) {
      if (!operation.security?.length) continue;
      const statuses = Object.keys(operation.responses ?? {});
      expect(
        statuses.includes('401'),
        `${method.toUpperCase()} ${path} requires credentials but documents no 401`,
      ).toBe(true);
    }
  });

  it('requires an unprotected operation to be provably public', () => {
    const unprotected = operations()
      .filter(({ operation }) => !operation.security?.length)
      .map(({ path, method }) => `${method} ${path}`)
      .filter((key) => !PROVABLY_PUBLIC.has(key));
    expect(unprotected, `not declared public and not protected: ${unprotected.join(', ')}`).toEqual([]);
  });

  it('declares the security schemes its operations reference', () => {
    const declared = new Set(Object.keys(document.components?.securitySchemes ?? {}));
    for (const { path, method, operation } of operations()) {
      for (const requirement of operation.security ?? []) {
        for (const scheme of Object.keys(requirement)) {
          expect(declared.has(scheme), `${method.toUpperCase()} ${path} references undeclared scheme "${scheme}"`).toBe(true);
        }
      }
    }
  });
});
