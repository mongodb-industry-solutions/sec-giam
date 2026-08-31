# v39 definition of done: item by item

Walked at the end of P12, before hand-over. Each item records what was actually checked and how, not
whether it feels finished. Where something is unverified it says so and says why, because an item
marked done on the strength of an assumption is worse than one marked blocked.

**Two states only.** Verified means a test, a command or a reading of the code established it.
Blocked means it cannot be established in this environment yet, and names what is missing.

---

## The blocker, stated once

`GIAM_KMS_LOCAL_MASTER_KEY` is not set in `.env`, which is dotenvx-encrypted. Without it the
authority cannot open its database, so every item below that needs a running system is blocked on one
configuration line rather than on any code.

A throwaway key would not help: queryable-encryption data written under one master key is unreadable
without it, so seeding with a temporary key produces a database nobody can read afterwards. The key
has to be the durable one, and setting it belongs to whoever owns the environment.

---

## Verified

| # | Item | How it was established |
|---|---|---|
| 1 | No credential store, token issuance, signing key, role collection or permission assignment in either consumer | `extractionComplete.test.ts`, asserted against SOURCE rather than routes: a runtime test proves the endpoints are gone, a source test proves the capability is. It found eight surviving violations on its first run |
| 2 | LeafyPay's only identity code is a verifier, a claim reader, a permission catalog and a registration call | Same suite, plus the deletion of 4,473 lines across P11.1 to P11.6 |
| 6a-bis | No branch in GIAM names a consumer application | `dayOneInvariants.test.ts`. Consumer names were also removed from OpenAPI examples and comments, which the test did not object to and which a neutral product should not carry |
| 6b | Every port has at least two implementations and a fake, and adding one changes no calling module | `portSeams.test.ts`, which also asserts a port refuses an unknown implementation rather than degrading to a weaker one |
| 6d | `agent` distinct from `workload`, `tenantId` everywhere, `delegation` apart from `grant`, standard event format | `dayOneInvariants.test.ts`. These are the four that cannot be retrofitted cheaply, which is why they are asserted rather than reviewed |
| 7 | §10.1 lists every collection with its owning module, and the matrix test passes | `matrixCompleteness.test.ts`. Writing the section found five identity collections LeafyPay's setup was still creating and seven stale index sets; the setup was fixed, not the document |
| 9 | Every route in a committed OpenAPI document, each citing its specification or stating none applies | `openapiContract.test.ts`, which also requires an example wherever a route returns content and forces every unprotected route onto a justified allowlist |
| 11 | LeafyPay accepts a conforming token from an issuer that is not this authority | `foreignIssuer.test.ts`, standing up a genuinely different issuer with its own keys and discovery. **It found a real defect**: both verifiers required an audience claim without comparing it, so any token from the trusted issuer opened the application whichever client it was for. Both are fixed |
| 16 | No consumer seeder writes an identity, credential, role, assignment, client, key or API key | `extractionComplete.test.ts`. A login deriver was still living in LeafyPay's seed module and is gone |
| 19 | The simulator resolves per-role tokens by token exchange and `DEMO_PASSWORD` is gone from the frontend | Source, and `constants.test.ts` now asserts the ABSENCE of the password rather than its value |

---

## Blocked on the database

Each of these has its code written and its test written. What is missing is a running system to
exercise them against.

| # | Item | State |
|---|---|---|
| 3 | BankCore workforce access control; machine and interactive grants never substitute; a foreign realm's token refused | Code and tests written (`staffLogin.test.ts`, `tppAuthorization.test.ts`). The realm-isolation half is now stronger than when it was written, because the audience check landed |
| 4 | Merchant SSO and CIBA against the authority with no change to its authenticator, oauth or session modules | Repointed by environment only, exactly as the plan required. Unrun |
| 5, 20 | LeafyWallet unmodified and working through the compatibility proxy, proven by its own suite | Not one file of the wallet was changed. The proxy is written with its allowlist and its rules. Unrun, and this is the item I would want run first |
| 6, 6a, 6c | Standalone demo realm with no financial concept; one pipeline across all principal kinds; horizontal scale with no KMS on the default configuration | The multi-replica property was measured in P8 and recorded in the runbook with real numbers, including an unflattering one. The rest is unrun since |
| 8, 15 | All three databases rebuild from `--reset` + reseed with no manual step | Setup and seed are the only path and no ad-hoc migration exists. Unrun |
| 12 | Every principal that signs in today signs in after, with the same credentials and permissions | `parityGate.test.ts` covers all 68. **P12.2 found the binding that would have broken this**: no identity carried `accountHolderRef`, so no principal was bound to any party. Fixed in the fixture; the test proves it once it can run |
| 13 | The login experience preserved: theming, roster, one-click per role, realm picker | `loginParity.test.ts` written for exactly this, asserting each affordance persona by persona. Currently skips |
| 14 | Authorized Applications and the audit timeline served entirely by the authority with no local copy | Written that way: the caller's own token is forwarded, nothing cached, nothing filtered locally. Unrun |
| 17 | Both validation models selectable per resource server, shared client package, revocation in each, and the negative cases | `tokenValidation.test.ts` covers the negatives. Half of this is now also covered by `foreignIssuer.test.ts`, which runs today |
| 18 | One session across the fleet, and a single logout ending all of them | The capability the platform did not have at all before. Unrun |

---

## Known, and deliberately not fixed

**One pre-existing unit failure.** `adminModules.test.ts` expects `card-issuer` among the modules the
provider administers, and `adminHelpers.ts` last changed before this work began. It is unrelated to
identity and it is left failing. Adjusting the assertion to make the count read 1340 of 1340 would
have been the wrong repair on somebody else's defect.

**The event bus package is namespaced to a consumer.** GIAM imports `@leafypay/eventbus`. Nothing in
its behaviour is coupled, but the name is, and a product claiming to be industry-neutral should not
depend on a package named after one of its consumers. Renaming it touches every service in the
repository, so it is recorded here rather than done quietly at the end of an unrelated phase.

**Token issuance latency is poor and the cause is known.** Client authentication verifies a
128-bit random secret with bcrypt at cost 12, which is the right cost for a human password and the
wrong one here. Measured, recorded in the runbook, and not changed: it alters stored credential
material and deserves its own change with its own reseed.
