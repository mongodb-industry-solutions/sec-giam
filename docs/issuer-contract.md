# The issuer contract

What a protected application depends on after the extraction, stated precisely enough that something
other than GIAM could satisfy it.

This document exists because "LeafyPay now depends on GIAM" is the wrong description of what
happened, and believing it would be a design mistake. LeafyPay depends on an **issuer contract**.
GIAM is one implementation of it. Anything that satisfies what follows can replace GIAM by changing
one environment variable, and the point of writing it down is that the claim is checkable.

---

## The dependency, in full

An application configures **one** value:

```
PSP_GIAM_ISSUER_URL = https://<authority>/realms/<realm>
```

Everything else is discovered. The application hardcodes no path beneath the issuer, because those
paths belong to the authority and it may reorganise them.

---

## 1. Discovery

The issuer serves OpenID Connect Discovery 1.0 metadata at
`${issuer}/.well-known/openid-configuration`, and RFC 8414 metadata at
`${issuer}/.well-known/oauth-authorization-server`.

Required members:

| Member | Why the application needs it |
|---|---|
| `issuer` | Compared against the `iss` claim of every token. Must equal the configured value exactly. |
| `jwks_uri` | Where the verification keys live. Never assumed from the issuer path. |
| `token_endpoint` | Where a client redeems a grant. |
| `authorization_endpoint` | Where a browser is sent to sign in. |

Both documents are **public**. They name endpoints; they disclose nothing.

---

## 2. The key set

`jwks_uri` serves an RFC 7517 key set of **public** keys, each carrying `kty`, `kid`, `use: "sig"`,
`alg`, and the algorithm's public parameters.

Three properties the application relies on:

- **Only public material crosses the wire.** No private key, no shared secret and no client
  credential is involved in verification. This is what makes a compromised resource server unable to
  mint a token, and it is not true of any scheme where the verifier holds a shared secret.
- **The set is complete for the realm.** Every key that may have signed a live token appears,
  including keys held by other replicas of the authority. A verifier resolving a `kid` against this
  set must never get "not found" for a token the authority itself issued.
- **A retired key stays published until every token it signed has expired.** Removing one earlier
  invalidates live sessions, and it is the single operational mistake that breaks local verification.

The application caches the set, keyed by `kid`, and refetches on an unknown `kid` at most once per
key per minute. On an unreachable authority it **serves from a stale cache** rather than failing
closed: an old public key can only validate signatures the authority itself produced, and the
alternative is a total outage of every application whenever the authority blinks.

---

## 3. The access token

RFC 9068, the JWT profile. Signed **RS256**.

| Claim | Requirement |
|---|---|
| `iss` | Exactly the configured issuer |
| `aud` | Contains the client this token was issued to |
| `sub` | The stable subject identifier |
| `exp`, `nbf` | Enforced with a small clock-skew allowance |
| `typ` | `at+jwt` in the header, so an ID token cannot be presented as an access token |
| `scope` | Space-delimited, per RFC 6749 |

### The one non-standard member: `permissions`

```json
"permissions": [
  { "resource": "transactions", "action": "view" },
  { "resource": "cards", "action": "manage" }
]
```

Entries are drawn from the catalog the application itself registered (§5). No standard defines this
claim, and that is stated rather than dressed up: OAuth scopes describe what a CLIENT was authorised
to request, and this describes what the PRINCIPAL may do at this resource server. Conflating the two
is a common and expensive mistake, because a client's scope is not a person's authority.

An application receiving a token with no `permissions` claim **denies everything**. An absent claim
is not an unrestricted one.

### Optional members the application will use if present

| Claim | Meaning |
|---|---|
| `session_epoch` | Lets a whole generation of tokens be refused without listing them |
| `sid` | The session, so a logout can revoke everything issued under it |
| `act` | RFC 8693 delegation chain: who is acting, for whom |
| `cnf` | Sender constraint, when tokens are bound to a certificate or key |

---

## 3b. The demo roster, and why it is scoped per client

`GET {issuer}/login-context?client_id=…` is what the hosted sign-in screen renders: the realm's
branding, the federated providers on offer, and, in a demonstration realm, a roster of ready-made
personas.

The roster is narrowed by the **client id already present in the authorization request**, so nothing
extra is passed. Each client record carries a `demoRoster` listing the role names its screen should
offer, and the useful set differs sharply per application:

| Application | Offers | Why |
|---|---|---|
| The provider's own portal | its staff and its customers | a merchant signs in as a customer who owns one |
| A third party's app | customers only | its testers are users, never the provider's back office |
| The authority's console | who administers identity, who audits it, one ordinary user | the rest administer nothing here |
| The bank | its own staff and account holders | no provider role exists in that realm at all |

Two properties matter. The list comes from the **client record**, never from the query, so a caller
cannot widen its own roster by asking for more. And a client that declares nothing gets every featured
persona in the realm, which is what a realm with no application-specific screen should do.

Every offered role carries **at least two** personas, so a screen demonstrates a role rather than a
person.

---

## 4. What the authority must NOT do

Constraints, not preferences. An implementation violating any of these is not a drop-in replacement.

- **Never issue a token whose `permissions` name a resource the application did not register.** The
  application would deny it anyway, but the grant would be invisible to whoever created it.
- **Never reuse a `kid` for a different key.** A verifier caches by `kid`; reusing one is
  indistinguishable from a forgery and cannot be detected by the verifier.
- **Never sign with an algorithm the key set does not declare for that `kid`.**
- **Never require the application to hold a secret in order to verify.** The moment verification
  needs one, a compromised application can mint tokens.

---

## 5. What the application owes the authority

One call, at boot:

```
PUT ${authority-origin}/admin/resource-servers/${name}/permissions
{ "realm": "...", "audience": "...", "permissionCatalogVersion": "1", "permissions": [ ... ] }
```

The catalog ships in the application's own code, because only the code containing a guard can say a
permission exists. The authority grants those permissions to roles; the application stores no
assignment and makes no grant.

The call is **idempotent** and **non-fatal**. An unreachable authority at boot must not stop the
application serving requests that carry already-valid tokens, because those verify against a cached
key set and need the authority for nothing.

---

## 6. Replacing the authority

Point `PSP_GIAM_ISSUER_URL` at any conforming issuer. There is no other coupling.

**If the replacement cannot emit the `permissions` claim** there are two supported answers, in order
of preference:

1. **Put GIAM in front of it as a broker.** GIAM federates upstream to the other provider and mints
   its own tokens, so the application still sees one issuer and one contract. This is the designed
   path and it is why the broker exists.
2. **Fall back to RFC 7662 introspection** against an authority that can resolve entitlements. This
   costs a network call per request and makes the authority a hard dependency on the hot path. It is
   an escape hatch, not a mode to choose.

---

## 7. How this is verified

The contract is not a document that describes the code; it is a document the code is tested against.

- The application's verifier refuses `alg: none`, symmetric algorithms, and the `jku`, `jwk`, `x5u`
  and `x5c` header parameters, each with its own negative test.
- A token from an unconfigured issuer is refused even when its signature is valid.
- An unknown `kid` is refused after one rate-limited refetch.
- A stale key set is served during a simulated outage rather than failing closed.
- A conforming token from an issuer that is **not** GIAM is accepted, which is the assertion that
  makes this document a contract rather than a description.
