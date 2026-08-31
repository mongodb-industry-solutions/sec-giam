# The identity and access authority

Every identity, credential, role, session, token, grant and security event on the platform lives here.
The applications around it authenticate nobody: they verify tokens against a published key set and
read claims.

This directory documents the product. The decisions behind it are ADR-070 to ADR-080 in
[docs/engineering-proposal.md](../../docs/engineering-proposal.md); the plan that produced it is the
v39 specification.

---

## What to read, in order

| Document | Answers |
|---|---|
| This file | What it is, what it refuses to be, and where the boundaries are |
| [issuer-contract.md](issuer-contract.md) | What a relying party can rely on: tokens, keys, discovery, verification |
| [runbook.md](runbook.md) | How to configure, scale and operate it, and every documented weakness |
| The OpenAPI document at `/doc` | Every route, with the specification each one implements |

---

## What it is

An authority for **every kind of principal**, from the first release. A customer, a fraud analyst, a
backend service, a registered application, an agent and a workload are all principals here, and the
difference between them is the authentication method rather than a separate pipeline. That is not
symmetry for its own sake: a second pipeline is how one of the two ends up without an audit trail,
and it is always the machine one.

It speaks the standards rather than resembling them. OAuth 2.0 and OpenID Connect for tokens, SCIM
2.0 for provisioning, RFC 8693 for delegation, RFC 7591 and 7592 for registration, RFC 9457 for
errors. Where a route has no governing standard, its API description says so in those words, so a
bespoke endpoint and a conforming one are never mistaken for each other.

---

## What it refuses to be

**It carries no financial vocabulary.** No payment, card, merchant, account or transaction concept
appears in its model, its API or its policy language. It authorises access to `cardData` without
knowing what a card is, because a resource server declares its own catalog and the authority only
records who may reach it. This is the property that makes it reusable, and it is enforced rather than
intended.

**It never decides what a consuming application means.** It stores an opaque reference binding a
principal to an application's own record, hands it back in a token, and resolves it against nothing.
The application finds its own data; the authority never learns what the reference names.

**It gates no capability on the environment.** No code asks whether this is production. Hardening is
configuration, and a weaker configuration warns and is documented rather than refusing to start. A
capability that exists only outside production has never been tested where it matters.

**It is not a policy engine for business rules.** It answers whether a principal holds a permission.
Whether a payment should proceed, whether a case may be closed, whether an agent may operate at a
given risk class: all of those belong to the systems that understand them.

---

## The boundaries that matter

**Consent is two different words.** A grant here is a principal allowing an application to use scopes
on their behalf, and it moved. Account-access consent under the payment-services rules is regulated
business data belonging to the institution holding the account, and it did not move and must not. The
two share a word and nothing else.

**A party is not a principal.** A business record about a person stays with the application that
serves that person. What moved is the credential, the role and the session.

**A catalog is not a role table.** An application declares the resources and actions it enforces.
Who holds which role is the authority's, because that is an access decision. An application holding
one is a second decision point that will eventually disagree with the first.

---

## Operating it in one paragraph

It scales horizontally with no KMS, no shared volume and no shared secret: each replica holds its own
signing key and publishes only the public half, and a realm's key set is the union of them. Set
`GIAM_KMS_LOCAL_MASTER_KEY` and point `GIAM_DB_URI` at a database it owns alone. The database is built
by `setup` and `seed` and by nothing else. Read the runbook before deploying more than one replica:
the publication grace period must be at least the access-token lifetime, or scaling down signs live
users out for a reason nobody will connect to the deployment that caused it.

---

## How the extraction stays done

`test/giam/backend/unit/extractionComplete.test.ts` asserts against the SOURCE of the consuming
applications that none of them mints a token, stores principal credentials, seeds principals, creates
an identity collection, publishes issuer metadata or holds a role table. A runtime test would prove
the routes are gone; this proves the capability is gone, which is the thing that creeps back.

Exceptions are named one by one, never pattern-matched, so a second offender cannot hide behind an
allowance made for the first. There are four, and each authenticates a SYSTEM to the platform rather
than saying who a person is: the bank's Open Banking event signing and its published key set, its
third-party registration registry, and the provider integration registry.
