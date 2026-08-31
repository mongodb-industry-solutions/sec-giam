import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { config } from '../config';

// GIAM's API documentation is a deliverable, not a by-product: it is the contract other teams
// integrate against, and the quality bar is enforced in CI rather than by review.
//
// Every route falls in one of two categories and must say which in its description:
//
//   1. Standard-defined. Path, method, parameter names, encoding, response shape and error codes
//      follow the specification VERBATIM, and the description cites the clause it implements. A
//      renamed field or a house error envelope on one of these is a defect, not a design choice.
//   2. No applicable standard. Plain REST, and the description says "no applicable standard"
//      explicitly, so the absence is a recorded decision rather than an omission.

async function swaggerPlugin(fastify: FastifyInstance) {
  const servers = [
    ...(config.server.publicUrl ? [{ url: config.server.publicUrl, description: 'public' }] : []),
    { url: config.server.baseUrl, description: 'private, service to service' },
  ];

  await fastify.register(swagger, {
    openapi: {
      openapi: '3.1.0',
      info: {
        title: 'GIAM (General Identity and Access Manager)',
        version: '1.0.0',
        description: `
## Overview

GIAM is the identity authority for **people and systems equally**: employees, customers,
microservices, applications, AI agents and workloads. It is industry neutral, so nothing in its
model, its API or its policy vocabulary names a business concept belonging to the applications it
protects.

It is an identity **broker** as well as an authority: an application speaks one protocol (OIDC) to
one issuer, and GIAM federates behind that to an upstream provider, several at once if needed. Adding
one is a configuration record, not a change in any application.

## How to read this document

Every operation declares its category:

| Category | Meaning |
|---|---|
| **Standard-defined** | Implements a published specification verbatim. The description cites the RFC or specification clause. The error shape is the specification's own, never a house envelope. |
| **No applicable standard** | Plain REST: plural resources, correct verb semantics, \`PATCH\` for partial updates, RFC 9457 \`application/problem+json\` errors, \`ETag\` and \`If-Match\` on mutable resources, cursor pagination, \`Idempotency-Key\` on unsafe operations. |

Public protocol endpoints live under a realm's issuer path; administrative ones live under
\`/admin/\`, so a reader can tell them apart from the URL alone.

## Realms

A realm is a trust and key boundary: its own issuer, its own signing keys, its own JWKS. A token
minted in one realm is refused by another, which is what makes an institutional boundary real rather
than declared. A tenant is a data boundary INSIDE a realm.

## Token validation

Both models are supported and the choice belongs to the resource server, per operation:

- **Decentralised.** Verification uses only the public keys GIAM publishes, downloaded and cached by
  the client. No secret at the client, no network call per request, and a GIAM outage does not
  invalidate an already-issued token.
- **Centralised.** Introspection at GIAM, so revocation is immediate and the answer reflects current
  account status rather than what was true at issuance.

The recommended default is to verify locally on every request and introspect only where the decision
is expensive to get wrong.
`,
      },
      servers,
      tags: [
        { name: 'discovery', description: '**Standard-defined.** OIDC Discovery 1.0 and RFC 8414 metadata, and the RFC 7517 key set.' },
        { name: 'oauth', description: '**Standard-defined.** Authorization, token, refresh, introspection, revocation, userinfo, token exchange.' },
        { name: 'authentication', description: '**Standard-defined where a specification exists.** Interactive sign-in, passwordless, backchannel authentication, enrolment, logout.' },
        { name: 'consent', description: 'Scope grants a principal has given a client, and delegations a principal has given an agent.' },
        { name: 'scim', description: '**Standard-defined.** SCIM 2.0 provisioning, extended to agents, applications and service identities.' },
        { name: 'realms', description: '**No applicable standard.** Realm and federation configuration.' },
        { name: 'directory', description: '**No applicable standard.** Principal, agent, tool and tenant administration outside the SCIM surface.' },
        { name: 'authorization', description: 'Resource servers, permission catalogs, roles, assignments, policies, and the decision endpoint.' },
        { name: 'keys', description: '**No applicable standard.** Signing key inventory, custody and rotation.' },
        { name: 'sessions', description: '**No applicable standard.** Active sessions and forced termination.' },
        { name: 'audit', description: '**No applicable standard.** Security event query, and the standard event delivery streams.' },
        { name: 'provisioning', description: '**No applicable standard.** Outbound lifecycle delivery, and the reconciliation that corrects a missed one.' },
        { name: 'workload', description: 'Workload identity federation, attestation state and credential exchange.' },
        { name: 'privilege', description: '**No applicable standard.** Time-bound privilege elevation and its approvals.' },
        { name: 'admin', description: '**No applicable standard.** Diagnostics, posture and operational surface. Not part of the integration contract.' },
        { name: 'system', description: '**Infrastructure, not API.** Health and readiness for deployment probes.' },
      ],
      components: {
        securitySchemes: {
          // An access token GIAM itself issued, verified against the realm's published key set.
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          // RFC 6749 client authentication at the token endpoint.
          clientBasic: { type: 'http', scheme: 'basic' },
          // RFC 8705: the client is identified by the certificate it presented on the TLS connection.
          // `mutualTLS` is an OpenAPI 3.1 scheme type and the bundled 3.0 typings do not know it yet.
          mtls: { type: 'mutualTLS' } as never,
        },
      },
    },
  });

  if (!config.app.docsEnabled) return;

  await fastify.register(swaggerUi, {
    routePrefix: '/doc',
    uiConfig: {
      docExpansion: 'list',
      deepLinking: true,
      displayRequestDuration: true,
      filter: true,
      tryItOutEnabled: true,
    },
    theme: {
      title: 'GIAM API',
      css: [{
        filename: 'giam-topbar.css',
        content: [
          '.topbar-wrapper .link span:not([class]) { display: none; }',
          '.topbar-wrapper .link svg { display: none; }',
          '.topbar-wrapper .link::after { content: "GIAM"; font-size: 1.15rem; font-weight: 700; color: #00ED64; margin-left: 8px; letter-spacing: 0.01em; }',
          '.swagger-ui .topbar { background-color: #001E2B; }',
        ].join('\n'),
      }],
    },
    staticCSP: true,
    transformStaticCSP: (header) => {
      const port = String(config.server.port);
      return `${header}; connect-src 'self' http://localhost:${port} http://127.0.0.1:${port}`;
    },
    transformSpecification: (spec) => spec,
    transformSpecificationClone: true,
  });
}

export default fp(swaggerPlugin, { name: 'swagger' });
