# GIAM runbook

Operating the identity and access authority. This is the fourth of the four places a weaker
configuration surfaces: the startup log, the `GET /admin/posture` endpoint, the console banner, and
here. A warning nobody sees is the same as no warning.

---

## What GIAM decides, and what it does not

GIAM does not decide what you are allowed to run. There is no "development only" capability and no
code that asks which environment it is running in. Hardening is configuration, and a weaker
configuration **warns and is documented**; it does not refuse to start.

That means a minimal deployment is a correct deployment, not a crippled one, and a hardened deployment
is the same build with different configuration. What you turn on is policy; the capability is always
present.

---

## Configuration

Everything is prefixed `GIAM_`. Nothing is derived from another service's configuration.

### Storage

| Variable | Purpose | Default |
|---|---|---|
| `GIAM_DB_URI` | Connection string. Falls back to `MONGODB_URI` | the platform cluster |
| `GIAM_DB_NAME` | Database. Always distinct from any other service's | `giamdb` |
| `GIAM_DB_KEYVAULT` | Key vault **collection**, inside that same database | `keyVault` |
| `GIAM_CRYPT_SHARED_LIB_PATH` | Encryption shared library | falls back to the platform value |
| `GIAM_QE_TEXT_SEARCH` | Substring search on encrypted names. Needs server and library 8.2+ | `true` |

Sharing a cluster is not sharing a database. GIAM never reads another service's collections and no
other service reads GIAM's.

### Key custody

| Variable | Purpose | Default |
|---|---|---|
| `GIAM_KEY_PROVIDER` | `instance-local`, `kms`, `shared-store` or `filesystem` | `instance-local` |
| `GIAM_KEY_STORE_DIR` | Where node-custody providers keep private material | `./keys` |
| `GIAM_INSTANCE_ID` | This replica's identity, for its key lease | the hostname |
| `GIAM_KEY_LEASE_SECONDS` | How long a replica's claim on its key lasts | `300` |
| `GIAM_KEY_HEARTBEAT_SECONDS` | How often it renews | `60` |
| `GIAM_KEY_PUBLICATION_GRACE_SECONDS` | How long a lapsed key stays published | `3600` |
| `GIAM_KEY_WRAPPING_KEY` | Key-encryption key. Required by `shared-store` | none |
| `GIAM_KEY_AWS_KEY_ARN` | Required by `kms` | none |
| `GIAM_REPLICAS` | Declared replica count. Used to report posture, never to refuse to start | `1` |

### Operations

| Variable | Purpose | Default |
|---|---|---|
| `GIAM_PORT` | API port | `8085` |
| `GIAM_BASE_URL` | Private, service to service | `http://127.0.0.1:8085` |
| `GIAM_PUBLIC_URL` | Public. **A realm issuer URL is built from this** | none |
| `GIAM_FRONTEND_URL` | The console | `http://localhost:8086` |
| `GIAM_CORS_ORIGIN` | Browser origins allowed to call the API | the console |
| `GIAM_ADMIN_TOKEN` | Credential for `/admin/*`. Unset means the surface refuses every call | none |

---

## Scaling

**The default scales horizontally with no KMS, no shared volume and no shared secret.** This is worth
stating plainly because it is the one property people assume an identity service cannot have.

Each replica holds its own key pair on its own node and registers only the **public** half. A realm's
JWKS is the union of every active public key, so every replica publishes an identical set and a token
signed by one verifies at any other, at every resource server, and after a restart.

The private key never leaves the node and never touches the database. That is better isolation than a
shared key, not worse: compromising a node yields one key, and revoking it removes one entry from the
set rather than rotating the signer for the whole deployment.

**Scale-up** needs nothing. A new replica's `kid` is unknown to a cached verifier, and the rate-limited
refetch on an unknown `kid` handles it.

**Scale-down** is where the lease matters. A replica that goes away stops renewing; its key stops being
offered for signing immediately and stays **published** for `GIAM_KEY_PUBLICATION_GRACE_SECONDS`.

> **Set the publication grace to at least the maximum access-token lifetime.** Shorter, and a
> scale-down invalidates tokens that have not expired, which signs live users out for a reason nobody
> will connect to the deployment that caused it. The posture endpoint reports this as
> `publication_grace_too_short`.

---

## Measured performance

Numbers, not claims. Taken on a developer machine against a shared Atlas cluster, with **two
replicas** of the authority on the default `instance-local` key custody. Treat the absolute values as
this environment's; the shape of them is what matters.

### The multi-replica claim, verified

| Property | Result |
|---|---|
| Replicas sign with distinct keys | yes |
| Published key sets identical from either replica | yes |
| Both signing keys present in the published set | yes |
| Token signed by replica A, accepted at replica B | yes |

That is the whole scalability position, measured rather than asserted: no KMS, no shared volume, no
shared secret, and a token from one replica verifies at the other.

### Latency

| Operation | Sequential (p50) | 20 concurrent (p50) | 20 concurrent (p95) |
|---|---|---|---|
| Token issuance (client credentials) | 1341 ms | 7710 ms | 9157 ms |
| Introspection | **7 ms** | 7110 ms | 8860 ms |
| Key set fetch | 239 ms | — | — |

### What these numbers say, including the unflattering part

**Introspection at 7 ms sequentially is the number that matters most**, because it is the cost a
resource server pays for the authoritative answer. It makes the hybrid recommendation practical: verify
locally by default, introspect on the operations where being wrong is expensive, and the second is
cheap enough not to be an excuse.

**Token issuance at 1.3 seconds is poor, and the cause is known.** Client authentication verifies the
secret with bcrypt at cost 12. That is the right cost for a password, and the wrong one here: bcrypt's
cost parameter exists to slow brute force against a LOW-ENTROPY human-chosen secret. A client secret is
128 bits of randomness, so no attacker is guessing it, and the work factor buys nothing while costing
roughly a quarter of a second per verification.

Under concurrency it compounds, because the hashing is CPU-bound on a single-threaded event loop: 20
concurrent requests queue behind each other, which is exactly the p50 of 7.7 seconds above.

**The fix, not applied here and recorded rather than quietly deferred:** verify machine credentials
with a fast keyed digest (HMAC-SHA256 over the secret with a server-held key) instead of bcrypt, and
keep bcrypt for human passwords where it belongs. It is the same reasoning as the API-key question in
the data model, and it changes stored credential material, so it deserves its own change with its own
reseed rather than being slipped into a phase about something else.

Until then, a deployment expecting heavy machine traffic should raise the access-token lifetime for
service clients so tokens are issued less often, which trades a longer revocation window for the
throughput.

---

## Documented limitations

Every entry here also appears as a posture finding with the same code, so it can be alerted on rather
than remembered.

### `key_path_may_not_be_shared`

`GIAM_KEY_PROVIDER=filesystem` with more than one declared replica.

The filesystem provider keeps one key pair at a configured path. If that path is genuinely shared
across replicas, this is correct. If it is not, each replica signs with a key the others do not
publish, and verification fails **intermittently**, depending on which replica served the request.
That is the worst failure shape there is: it looks like a flaky network.

The provider exists for migration from the platform's current signing key layout. Prefer
`instance-local`, which needs no shared path at all.

### `publication_grace_too_short`

See the scaling note above.

### `administration_closed`

`GIAM_ADMIN_TOKEN` is unset, so `/admin/*` refuses every call with 503.

This is deliberate. An unconfigured administrative surface is **closed**, not open: publishing
diagnostics to anyone who asks because nobody set a variable is the failure this prevents. It refuses
identically in every deployment, because no behaviour here depends on which environment this is.

### `encryption_library_missing`

`GIAM_CRYPT_SHARED_LIB_PATH` points at nothing.

The whole database connection fails, and every route then reports an outage rather than an encryption
problem. This has cost this project time before, which is why it is checked at startup rather than at
the first encrypted read.

### `client_enforcement_soft`

A realm's `clientEnforcement` is `soft`, or `GIAM_CLIENT_ENFORCEMENT=soft` and the realm inherits it.

An unregistered client is admitted rather than refused. It is **admitted, marked and limited**: no
`permissions` claim, no `roles` claim, no refresh token, and the scope cut to `openid`, so it reaches
nothing a registration would have granted it. Every admission writes a `client.soft_admission`
security event naming the presented client id, the hashed address, the endpoint and the reduction.

Soft mode relaxes exactly one thing: **not being registered yet**. A wrong secret on a known client,
a revoked or suspended client, an unregistered redirect URI and an expired code are refused
identically in both modes. It is offered at the token and authorization endpoints only, never at
introspection or decoupled authentication.

This is an onboarding ramp with evidence, not a security setting, and it is meant to be temporary.
Query the trail for `action=client.soft_admission`, register everything it names, then set the realm
back to `strict`.

### `storage_unreachable`

Protected routes answer **503**, not 401, so an operator reads "the directory is unreachable" instead
of chasing a credentials problem that does not exist. `/health` and `/admin/posture` keep answering:
the report is needed most at exactly the moment the database is gone.

---

## Building the database

`setup/` and `seed/` are the only supported way. There is no manual migration and no ad-hoc script.

```
npm run setup:db --prefix giam/backend            # create collections, indexes, DEKs
npm run setup:db --prefix giam/backend -- --reset # drop and rebuild
npm run setup:seed --prefix giam/backend          # reference and demo records
npm run setup:check --prefix giam/backend         # validate
```

### Two traps worth knowing before they cost an afternoon

**Setup SKIPS a collection that already exists.** Changing an encrypted-fields map in code therefore
does nothing to a live collection: the field keeps its old configuration, and no read complains,
because the field is simply stored the old way. Changing an encrypted-fields map needs `--reset` or a
drop of that collection. `setup:check` detects the drift and says so.

**Dropping the database destroys the key vault and every DEK in it,** because the vault is a collection
inside it. Anything encrypted under those keys becomes unreadable. That is acceptable **here and only
here**, because setup plus seed are the only way this database is built and every record is
reproducible. It would not be acceptable for a database holding data that cannot be regenerated.

A dump of the database contains ciphertext and the wrapped DEKs together. That discloses nothing on
its own: the DEKs are themselves encrypted under the master key the KMS provider holds, and the master
key is what matters.

---

## Checking a deployment

```
curl -s $GIAM_BASE_URL/health | jq                                  # is it serving
curl -s -H "Authorization: Bearer $GIAM_ADMIN_TOKEN" \
     $GIAM_BASE_URL/admin/posture | jq                              # what is actually in force
curl -s -H "Authorization: Bearer $GIAM_ADMIN_TOKEN" \
     $GIAM_BASE_URL/admin/logs | jq -r '.lines[]'                   # recent warnings and above
```

`status: "degraded"` means **serving, with a stated weakness**. It does not mean broken. Read
`findings[]`: each carries a code you can alert on, the exact risk, and the remedy.

### What `--reset` does now, and why it is not just a convenience

`--reset` drops and recreates every collection the registry names, AND drops every collection it no
longer names, including the driver's encrypted-state collections whose parent is gone.

That second half was added in v40 because without it a reset was not a reset. A collection the model
had renamed away survived every one, and its `encryptedFields` still referenced data encryption keys
the rebuilt vault no longer held. Validation then reported a stale key on a collection nothing
reads, and the advice it gave, "rebuild with `--reset`", could never fix it, because the reset was
exactly what skipped it.

Guarded to `--reset` only. An ordinary `setup:db` run removes nothing.

**A reseed is idempotent.** Running `setup:seed` twice reports zero created and zero updated the
second time. If it reports updates on an unchanged fixture, something in a seeder is writing a
value that differs per run: a wall clock, or a freshly salted hash compared as if it were owned
data. Both of those were real and both were fixed in v40.

### The access token lifetime IS the revocation objective

Five minutes, by default, per realm. An access token is verified against the published key set
without touching the database, so revoking a session cannot reach one already issued: the worst case
propagation is exactly this lifetime. Shortening it shortens the exposure and costs more refreshes;
lengthening it does the reverse. Nothing else about revocation changes that trade.

For a resource server that needs to hear sooner, subscribe it to the signal stream on its `resource`
record, or poll `GET /realms/:realm/signals?since=<instant>`. Both carry the same events.
