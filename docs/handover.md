# v39 handover: the identity authority, ready for review

This branch (`giam`) extracts every identity, authentication, authorization, token, key and
security-audit concern out of LeafyPay and BankCore into a standalone authority at `giam/`.

**It is not merged, and this agent does not merge it.** The merge belongs to the repository owner.

---

## What to look at first

1. `giam/docs/README.md`, for what the service is and how it is shaped.
2. `giam/docs/issuer-contract.md`, for the contract every application now depends on.
3. `giam/docs/definition-of-done.md`, walked item by item with an honest verdict on each.
4. `giam/docs/runbook.md`, for operating it, including the posture endpoint.
5. `docs/engineering-proposal.md`, ADR-070 to ADR-080, for the decisions and their rationale.
6. `docs/technical-spec.md` §10 and §10.1, for the ownership matrix across the three services.

## State of the tests

Measured on the running fleet at the tip of this branch:

| Suite | Result |
|---|---|
| Unit | 1345 passed |
| Integration | 273 passed, 126 skipped |
| End to end | 116 passed |

Everything is green.

One failure was left standing at first handover, in `test/psp/frontend/unit/lib/adminModules.test.ts`,
and it turned out to be a real defect rather than a stale assertion. The module index filters on a
`hasModule` flag that was false for card issuing and account information, but both screens exist on
disk with subpages and the API client actively calls their endpoints. They were reachable by typing
the URL and missing from the only page that links to them. The flag says whether the provider offers a
screen, which is a different statement from where the capability's configuration is administered. It
predates this branch and is fixed in its own commit, separate from the identity work.

The skipped integration cases are the live suites, which skip unless the fleet is listening. They
were run against a live fleet and pass; they skip in an environment without one, by design.

## Things a reviewer should specifically check

These are the points where the work is most load-bearing, or where a mistake would be quietest.

- **Audience.** Access tokens name the resource server, not the client. Verifiers compare the
  audience rather than merely requiring one, in both LeafyPay and BankCore. An earlier revision of
  this branch had a check that accepted anything; that is what the portability proof caught.
- **Key separation.** The bank derives its keys from its own root and never from the platform's, and
  there is a test asserting a platform-minted token is refused by the bank.
- **What was deliberately not moved.** Account-access consent rows are untouched: only OAuth scope
  consent moved. Historical audit rows still resolve because subject identifiers reuse the existing
  reference strings rather than being reissued.
- **The compatibility proxy** (`psp/backend/src/modules/identity/controllers/authorityProxy.controller.ts`).
  It exists so one client that resolves business and authentication calls from a single base URL
  keeps working. It is deprecated on the day it was written, it forwards an explicit allowlist, and it
  makes no decision about any token. It goes when that client splits its base URL.
- **Separation-of-duties rationales.** These were compliance evidence in the old access-control model
  and now live in role descriptions and seed comments. Confirm they still read as evidence.

## Known limitations, stated rather than hidden

- The multi-replica measurement in P8.6/P8.7 is recorded with its real numbers, including the ones
  that are not flattering. Read them before promising latency to anyone.
- Text search on encrypted fields needs a matching runtime on both the driver and the server. Staging
  has been pinned below that in the past, which surfaces as a server error rather than a clear
  message. See the runbook.
- Configuration is documented in `giam/backend/env.example` and asserted by a test, so a new variable
  that is not documented fails the build. A weaker configuration warns and starts; it does not refuse.

## Before merging

The three databases are rebuilt from setup and seed only, and this branch changes the shape of all
three. A merge needs a `--reset` and a reseed, not an in-place upgrade; there is no migration path and
that was the deliberate choice recorded in the plan.
