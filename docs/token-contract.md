# The token contract

What a token issued by this authority carries, what each claim is for, and which specification
defines it. This is the artifact to hand somebody integrating a resource server.

**A claim not in this document is a defect.** `test/backend/unit/tokenContract.test.ts` asserts the
shapes exactly: an unexpected claim fails the suite, and so does a missing one.

**A claim is absent, never empty.** `roles: []` or `entitlements: []` would force every resource
server to distinguish "none" from "present but empty", and that ambiguity is the kind that ends in an
inverted conditional.

---

## Access token

Header: `alg: RS256`, `typ: at+jwt` (RFC 9068 2.1), `kid`. Verification refuses `alg: none`, any
symmetric algorithm, a missing or mismatched `typ`, and any of `jku`, `jwk`, `x5u`, `x5c`, because a
token nominating its own verification key is a token asserting its own authenticity.

| Claim | Required | Defined by | What it is for |
|---|---|---|---|
| `iss` | yes | RFC 7519 4.1.1, RFC 9068 2.2 | Who minted it. Compare against the issuer you discovered, so a token from another realm cannot be replayed here. |
| `sub` | yes | RFC 7519 4.1.2 | Who it is about. A person's subject id, or the client's own id for `client_credentials`. |
| `aud` | yes | RFC 7519 4.1.3 | The RESOURCE SERVERS this token is for, not the client that asked. Compare it against your own registered audience. |
| `exp` | yes | RFC 7519 4.1.4 | When it stops being valid. Minutes, because local verification has no other bound. |
| `iat` | yes | RFC 7519 4.1.6 | When it was minted. Also the earliest valid instant: no `nbf` is emitted, because it was always equal to this. |
| `jti` | yes | RFC 7519 4.1.7 | The token's own unique name. Use it to enforce one-time use, or to name the exact token in an incident. **Not a flow identifier**: one authorization flow mints many tokens, each with its own `jti`. |
| `client_id` | yes | RFC 9068 2.2 | Which application asked. Differs from `sub` on a delegated token, and that difference is the audit question. |
| `scope` | yes | RFC 6749 3.3 | What was GRANTED, space delimited. May be narrower than the client requested. |
| `auth_time` | when a person authenticated | OIDC Core 2 | When the authentication happened. Demand a recent one for a sensitive operation. |
| `acr` | when a person authenticated | OIDC Core 2 | How strongly: `aal1`, `aal2`, `aal3` (NIST SP 800-63). Demand a stronger one for a sensitive operation. |
| `amr` | when a person authenticated | RFC 8176 | By what means: `pwd`, `otp`, `swk`, plus `mfa` when more than one factor was involved. |
| `roles` | when the subject holds any | RFC 9068 2.2.3.1, RFC 7643 4.1.2 | **The default form.** Expand these at your own decision point. Three roles instead of three hundred entitlements is the only form that fits in a header. |
| `entitlements` | only when the client narrowed | RFC 9068 2.2.3.1, RFC 7643 4.1.2 | `resource:action` strings, present only when the client asked for LESS than its roles grant. Always a subset of what the roles allow: asking can never widen. |
| `sid` | when there is a session | OIDC Back-Channel Logout 1.0 | The session this token belongs to. Introspect it to learn whether access is still live. Standard name, and carrying it in an access token is this authority's extension. |
| `act` | on a delegated token | RFC 8693 4.1 | Who is really acting. Members are `sub` and `client_id`, nesting through `act` for a chain. |
| `grant_id` | when a grant exists | OIDF Grant Management | The consent this token was issued under. Introspect it for the authoritative current state, including revocation and constraints that changed since issuance. Absent for `client_credentials` and for a first-party client, and that absence means there is nothing to introspect. |
| `authorization_details` | when the grant is constrained | RFC 9396 | Structured constraints a scope cannot express: a value ceiling, allowed resources, a transaction binding. Already filtered to the audience this token addresses, per 9.1, so everything present is for you. **A `type` you do not recognise MUST be refused, never ignored**: the specification does not say what to do with one, and ignoring it makes a token limited to a ceiling indistinguishable from a token with none. `packages/giam-client` fails closed on it. |

### Private claims

Three, and there is no specification behind them. All are declared in the discovery document's
`claims_supported` so a consumer can discover them rather than guess.

| Claim | What it is for |
|---|---|
| `session_epoch` | A generation counter on the principal. Refuse a whole generation of tokens at once by comparing it, which is what makes "sign out everywhere" work without listing outstanding tokens. |
| `admin_realms` | Realm NAMES this subject may administer besides the issuing one. Widens nothing: every request against a named realm is re-decided against the stored grant. |
| `account_holder` | An opaque reference to the business record a self-scoped principal owns. This authority never resolves it and does not know what it names. |

### Size

Claims are capped at **2 KB** and issuance FAILS above it rather than emitting a token that a proxy
will cut. That is about a 3.1 KB token, and it is breached at roughly 84 expanded entitlements.
Carry roles.

---

## Refresh token

Header `typ: rt+jwt`. Opaque to the client by RFC 6749 6, so every claim in it is this authority's
own. Nothing is stored: `sid` plus `gen` is everything redemption needs.

| Claim | What it is for |
|---|---|
| `iss`, `sub`, `jti`, `iat`, `exp` | As above. |
| `aud` | The issuer itself. Redeemed here, accepted nowhere else. |
| `sid` | The session it rotates against. |
| `gen` | The session's refresh generation. A lower one on redemption means a rotated token was replayed, and the whole session is deleted on the assumption of theft. |

---

## ID token

Header `typ: JWT`, per OIDC Core, which does not use `at+jwt`.

Carries `iss`, `aud` (the client), `sub`, `jti`, `iat`, `exp`, `nonce` when one was sent, and the
authentication context (`auth_time`, `acr`, `amr`).

**No profile claims.** OIDC Core 5.4: the claims requested by the `profile`, `email`, `address` and
`phone` scopes are returned from the UserInfo endpoint when an access token is issued, which in the
authorization code flow is always. Call `/realms/{realm}/protocol/openid-connect/userinfo` for
`name`, `preferred_username` and `email`, and note that what comes back is bounded by the granted
scopes.

`preferred_username` is a display shorthand, not an identifier: OIDC Core 5.1 says an RP "MUST NOT
rely upon this value being unique". The identifier is `sub`.

---

## Narrowing what you receive

Two request parameters, both narrowing only, and neither can widen anything.

- **`resource`** (RFC 8707), on the authorization or token request: which API the token is for. It
  intersects the client registration's audience, and a resource outside it is refused with
  `invalid_target` rather than silently dropped. Ask for one and your token is addressed to one API
  instead of every API in the realm.
- **`entitlements`**, space delimited, on the token request: hold less than your roles allow. This
  one is intersected and the remainder DROPPED rather than refused, so asking for one entitlement
  too many does not fail the whole request. The asymmetry with `resource` is deliberate: dropping
  keeps a narrow request worth making, while a wrong audience means you have the wrong idea of what
  you are talking to, and a token for the wrong API produces a 401 you cannot diagnose.

---

## How to verify

Two ways, and neither is right in general, which is why both exist.

**Locally, against the published key set** at `/realms/{realm}/protocol/openid-connect/certs`. Costs
nothing per request and keeps you serving when the authority is unreachable. Answers "was this signed
by the authority and is it within its lifetime". Check `iss`, `aud`, `exp` and `typ`, and refuse a
token missing any required claim above.

**By introspection**, at `/realms/{realm}/protocol/openid-connect/token/introspect`. Authoritative
about revocation, a suspended principal, and authority that changed since issuance. Costs a round
trip and puts the authority on your hot path.

Declare which you use in your resource registration (`validationMode`), and prefer local verification
by default with introspection where being wrong is expensive to undo.
