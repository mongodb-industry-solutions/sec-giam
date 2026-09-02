# GIAM

**General Identity and Access Manager.** The identity authority for people and for systems.

GIAM issues and verifies every token in a deployment: interactive sign-in for a person, client
credentials for a service, decoupled authentication for a device that has no browser. It is
deliberately **industry neutral**: no financial concept appears in its data model, its API or its
policy vocabulary, so the same authority serves a payments platform, a hospital or a logistics
network without being reshaped for any of them.

A **principal** is a person or a machine, treated the same way. Both enrol, both authenticate, both
carry credentials with a lifecycle, and both are authorised by the same policy engine. Nothing here
assumes a human is on the other end.

## What it does

- **OAuth 2.0 and OpenID Connect.** Authorization code with PKCE, refresh, client credentials,
  decoupled (backchannel) authentication, single logout, discovery and a published key set.
- **Realms.** Independent tenants, each with its own issuer URL, clients, principals and key set.
- **Per-instance signing keys.** Every replica holds its own private key on its own node and
  publishes only the public half, so a realm's key set is the union of them. No KMS, no shared
  volume, no shared secret, and it is correct on one replica and on twenty.
- **Queryable Encryption.** Identity attributes are stored encrypted in MongoDB and remain
  searchable, against GIAM's **own** key vault. An identity system that shares key material with
  what it protects has no compromise-containment story to tell.
- **Policy-based authorization.** Roles, scopes and attribute conditions evaluated in one engine.
- **An auditable security event stream**, recorded regardless of how (or whether) it is delivered
  onward.

## Layout

```
backend/     the authority (Fastify, TypeScript, MongoDB)
frontend/    the console: sign-in, consent, administration (Next.js)
packages/    shared libraries consumed through file: paths
  eventbus/          domain event bus (in-process, Kafka, RabbitMQ) with a MongoDB event store
  platform-links/    environment-aware service links and the demo client secret derivation
  giam-client/       the verifier a resource server uses against this authority
test/        vitest unit and integration suites
tools/       operator scripts (deploy, dev stop, SSO session harvest)
```

`packages/eventbus` and `packages/platform-links` are also vendored in the LeafyPay monorepo.
`clientSecretFor` in platform-links is a **cross-repo contract**: it derives the OAuth client secret
that GIAM seeds and that the consuming applications present. `test/backend/unit/clientSecretContract.test.ts`
pins the derivation with fixed vectors, so a drift between the copies fails a test here rather than
an authentication in a deployment.

## Quick start (local development)

Prerequisites: Node 22 or later, a MongoDB 8.2+ replica set or Atlas cluster (Queryable Encryption
needs a replica set), and the MongoDB `crypt_shared` library, version 8.2 or later.

```bash
npm run setup                 # installs the root, both packages and both apps

cp backend/env.example .env   # then edit: DB URI, master key, crypt_shared path
node -e "console.log(require('crypto').randomBytes(96).toString('base64'))"   # GIAM_KMS_LOCAL_MASTER_KEY

npm run setup:db              # create collections, indexes and DEKs
npm run setup:seed            # reference and demo records
npm run setup:check           # validate

npm run dev                   # backend on 8085, console on 8086
npm run dev:stop              # stop both, by port, checking ownership first
```

Rebuild the database from scratch with `npm run setup:reset` (which is `setup:db -- --reset` plus a
reseed). Setup **skips a collection that already exists**, so changing an encrypted-fields map in
code does nothing to a live collection until you reset; `setup:check` detects that drift and says so.

Other useful scripts:

```bash
npm run build        # packages, backend and console
npm run test         # unit and integration suites
npm run type-check   # every project, no emit
npm run openapi      # re-emit backend/openapi.json and spec-lint it
```

`backend/openapi.json` is a committed deliverable and CI fails if it does not match the source.

## Docker

```bash
docker compose up --build
```

The **backend image builds from the repository root**, not from `backend/`, because it installs the
shared packages under `packages/` through `file:` paths and needs `tsconfig.base.json`. The image
downloads `crypt_shared` 8.2.4 and sets both `MONGODB_CRYPT_SHARED_LIB_PATH` and
`GIAM_CRYPT_SHARED_LIB_PATH`; a wrong path there fails the whole database connection and surfaces as
a generic 503 on every route, so it is checked at startup instead.

Signing keys are never baked into an image. The instance-local provider generates this replica's key
at startup under `GIAM_KEY_STORE_DIR`, and only the public half is published.

The **console image builds from `frontend/`** and takes no routing decision at build time beyond the
two `NEXT_PUBLIC_*` API URLs: the console reaches the API same-origin through the Next.js rewrites,
resolved from `GIAM_API_PRIVATE_URL` inside the server, so one image is correct in every environment.

## Configuration

Every backend variable carries the `GIAM_` prefix, because GIAM is a product other deployments reuse
and it owns its own namespace. `backend/env.example` is the authoritative and commented list; this is
the shape of it. A unit test asserts the two directions match, so a variable cannot be read without
being documented or documented without being read.

The shortest working setup is three lines: a database URI, a master key, and the encryption library
path.

### Storage

| Variable | Default | Notes |
|---|---|---|
| `GIAM_DB_URI` | falls back to `MONGODB_URI` | Sharing a cluster is not sharing a database. |
| `GIAM_DB_NAME` | `giamdb` | GIAM never reads another service's collections. |
| `GIAM_DB_KEYVAULT` | `keyVault` | A collection inside that same database, with GIAM's own DEKs. |
| `GIAM_CRYPT_SHARED_LIB_PATH` | falls back to `MONGODB_CRYPT_SHARED_LIB_PATH` | Required. |
| `GIAM_QE_TEXT_SEARCH` | `true` | Substring search on encrypted names. Needs server and library 8.2+. |

### The master key

| Variable | Default | Notes |
|---|---|---|
| `GIAM_KMS_PROVIDER` | `local` | `local` or `aws`. |
| `GIAM_KMS_LOCAL_MASTER_KEY` | | 96 random bytes, base64. **Not rotatable in place.** |
| `GIAM_KMS_AWS_CMK_ARN`, `GIAM_KMS_AWS_REGION` | | With `aws`. |

Losing or changing the master key makes the database unreadable and the only recovery is `--reset`
plus a reseed. That is acceptable here, and only here, because setup and seed are the only way this
database is built and every record is reproducible.

### Signing key custody

| Variable | Default | Notes |
|---|---|---|
| `GIAM_KEY_PROVIDER` | `instance-local` | Also `kms`, `shared-store`, `filesystem`. |
| `GIAM_KEY_STORE_DIR` | `./keys` | Where the private half lives. |
| `GIAM_INSTANCE_ID` | the hostname | A stable per-replica identity. |
| `GIAM_KEY_LEASE_SECONDS` / `GIAM_KEY_HEARTBEAT_SECONDS` | `300` / `60` | |
| `GIAM_KEY_PUBLICATION_GRACE_SECONDS` | `3600` | At least the access-token lifetime, or scaling down signs live users out. |
| `GIAM_REPLICAS` | `1` | Reported in the posture endpoint, never used to refuse to start. |
| `GIAM_KEY_WRAPPING_KEY` / `GIAM_KEY_AWS_KEY_ARN` / `GIAM_KEY_AWS_REGION` | | Required by `shared-store` and `kms` respectively. |

### Operations

| Variable | Default | Notes |
|---|---|---|
| `GIAM_PORT` | `8085` | |
| `GIAM_BASE_URL` | `http://127.0.0.1:8085` | Private. What a resource server resolves discovery against. |
| `GIAM_PUBLIC_URL` | empty | Public. A realm's issuer URL is built from this; set it deliberately. |
| `GIAM_FRONTEND_URL` | `http://localhost:8086` | Where the sign-in, consent and admin screens live. |
| `GIAM_CORS_ORIGIN` | `http://localhost:8086` | |
| `GIAM_ADMIN_TOKEN` | unset | The credential for `/admin/*`. **Unset means closed, not open.** |
| `GIAM_ADM_USER` / `GIAM_ADM_PASS` | unset | Console sign-in. Only the hash is configured. |
| `GIAM_ADMIN_SHELL` | `true` | Whether the console may run an arbitrary command. |
| `GIAM_PROJECT_ROOT` | derived | The checkout the console runs scripts from. |
| `GIAM_SEED_DATA_DIR` | beside the code | Set in a container. |
| `GIAM_DOCS_ENABLED` | `true` | The API reference at `/doc`. |

### Client registration enforcement

What happens when a caller presents a client that is **not registered**. Configured per realm on the
realm record (`clientEnforcement`), with `GIAM_CLIENT_ENFORCEMENT` as the deployment default. The
default is **`strict`**.

| Mode | Behaviour |
|---|---|
| `strict` | The client is refused. Nothing about it is new. |
| `soft` | The client is admitted, marked and limited. |

**`soft` is an onboarding ramp with evidence, not a security setting, and it is meant to be
temporary.** It exists so a deployment can be brought up before every consumer has been registered
without the refusals being invisible. It is not "skip verification". A soft admission:

- **carries less authority**: no `permissions` claim, no `roles` claim, no refresh token, and the
  scope cut to `openid`, so it cannot reach anything a registration would have granted it;
- **is recorded**: a `client.soft_admission` security event naming the presented client id, the
  hashed address, the endpoint and the exact reduction. That event stream is the list of who still
  has to register;
- **degrades the posture**: `/api/v1/admin/posture` reports `client_enforcement_soft` per realm, and
  the console renders it as a banner like any other degraded finding.

Soft mode relaxes **exactly one thing: not being registered yet**. A wrong secret on a *known*
client, a revoked or suspended client, an unregistered redirect URI and an expired code are refused
identically in both modes. Soft admission is offered at the token and authorization endpoints only,
never at introspection or decoupled authentication.

| Variable | Default | Notes |
|---|---|---|
| `GIAM_CLIENT_ENFORCEMENT` | `strict` | `strict` or `soft`. A realm record may override it. |

### Registering a consumer

A consuming application needs three things: a client id, its secret, and a redirect URI registered
here that matches the one it builds. The **canonical variable names for any new consumer are
`GIAM_CLIENT_ID` and `GIAM_CLIENT_SECRET`**, and a new consumer should use those rather than invent a
third spelling. Existing consumers that read another name are not renamed for it; the convention
applies going forward.

Where a client is confidential, its secret is derived by `clientSecretFor(<client id>)` in
`packages/platform-links`, which is the same derivation this authority seeds and the consumer
presents. A deployment that would rather hold a literal secret sets the variable named in
`CLIENT_SECRET_REFS` for that client id, and the derivation yields to it.

### Event delivery

`GIAM_EVENT_BUS_ENGINE` (`in-process`, `kafka`, `rabbitmq`) and `GIAM_EVENT_BUS_TOPIC_PREFIX`, plus
`GIAM_KAFKA_*` or `GIAM_RABBITMQ_URL`. Security events are recorded regardless; this only controls
how they are delivered onward, which is why a single-node deployment has nothing to install.

### Console

The console reads `GIAM_API_PRIVATE_URL` at runtime (server-side, for the rewrites) and
`NEXT_PUBLIC_GIAM_API_URL` / `NEXT_PUBLIC_GIAM_API_PUBLIC_URL` at build time. An empty
`NEXT_PUBLIC_GIAM_API_URL` selects the same-origin proxy, which is what you want everywhere but a
laptop. `NEXT_PUBLIC_GIAM_NAME_PRIMARY` and `NEXT_PUBLIC_GIAM_NAME_SECONDARY` set the displayed name.

Simulator Mode adds three optional build-time values. `NEXT_PUBLIC_GIAM_URL_RELYING_PARTY` is the
registered application the simulator links to so the authorization code flow can be seen from the
side that consumes it (defaults to `http://localhost:8082` in development, empty elsewhere, and the
card then says the environment publishes none). `NEXT_PUBLIC_GIAM_URL_FRONTEND` overrides the address
put in the QR code, which otherwise is the live browser origin and is already correct almost
everywhere. `NEXT_PUBLIC_GIAM_REALM` names the realm whose discovery document the hub links to,
default `leafypay`.

## Deployment

Both images are built by Drone and deployed to Kubernetes through Kanopy, with per-environment
values under `environments/`. Secrets are held as Kubernetes secrets and never in a values file or
an image.

Two things to get right in a real deployment:

- **`GIAM_PUBLIC_URL`.** A realm's issuer URL is built from it, and an issuer that does not match
  what clients were configured with fails every verification.
- **`GIAM_KEY_PUBLICATION_GRACE_SECONDS`.** Set it to at least the access-token lifetime. Shorter,
  and scaling down invalidates tokens that have not expired, which signs live users out for a reason
  nobody will connect to the deployment that caused it. The posture endpoint reports this as
  `publication_grace_too_short`.

`npx tsx tools/kube.ts` is the operator helper: preflight checks, secret management and a
per-environment readiness report.

## License

Apache 2.0. See [LICENSE](LICENSE).
