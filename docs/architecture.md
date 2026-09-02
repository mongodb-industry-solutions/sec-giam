# Reference Data Architecture for Identity and Access Management (IAM) Systems

## Technical working document

| Field | Value |
|---|---|
| Objective | Define a reference data architecture for Identity and Access Management (IAM) systems and security platforms |
| Scope | Identity, authentication, federation, OAuth 2.0, OpenID Connect (OIDC), authorization, Privileged Access Management (PAM), governance, risk, controls, and audit |
| Target persistence | Database-independent logical model with a MongoDB-optimized projection |
| Alternative persistence | Normalized Structured Query Language (SQL) model and document-database equivalents |
| Status | Architectural working draft for technical validation |
| Date | September 2026 |

## 1. Executive summary

There is no single international standard that simultaneously defines the complete data model for IAM, identity storage, authorization policies, PAM, risk management, and compliance evidence. The industry generally uses a layered architecture: a conceptual IAM architecture, specialized interoperability standards, and a persistence model adapted to application access patterns.

The primary conceptual reference for this document is [IAM Reference Architecture (v2)](https://bok.idpro.org/article/id/76/) from IDPro. It is used as a conceptual architecture and shared vocabulary, not as a physical database schema. The model separates identity and access management from runtime use and includes concepts such as Identity Register, Identity Provider, credentials, authentication, authorization, access governance, metadata management, and audit repository. It also provides a basis for organizing authorization, governance, and risk-control concepts. (IDPro, 2021.) The bounded contexts, collections, JavaScript Object Notation (JSON) documents, indexes, and embedding or referencing decisions proposed later are implementation choices in this document for MongoDB; they must not be attributed to IDPro.

As an implementation-oriented reference, this document also uses [Identity and Access Management NIST Special Publication (SP) 1800-2 - NCCoE (National Cybersecurity Center of Excellence)](https://www.nccoe.nist.gov/publication/1800-2/VolB/index.html). The National Institute of Standards and Technology (NIST) structures the solution around an IAM workflow, an authoritative identity store, provisioning capabilities, and runtime systems that receive authorizations. (NIST NCCoE.)

### Fidelity statement regarding IDPro

The [IAM Reference Architecture (v2)](https://bok.idpro.org/article/id/76/) is a conceptual model for organizing IAM components and terminology. It is not intended to be a single physical schema or a MongoDB collection specification. Accordingly, this document retains the following IDPro concepts as reference concepts: Identity Register, Identity Management, Identity Provider, authentication, assertions, credentials, authorization, access governance, metadata management, relying parties, and audit repository.

The bounded-context decomposition, MongoDB collections, JSON examples, indexes, and storage patterns in this document are an implementation profile derived from that conceptual vocabulary. They do not modify, replace, or constitute a new version of the IDPro architecture.

The recommended implementation is to establish a canonical logical model with six bounded contexts. This is a design decision in this document and should be read as an operational decomposition compatible with IDPro terminology:

* Identity and Lifecycle.
* Authentication and Federation.
* Authorization and Entitlements.
* Privileged Access Management.
* Governance, Controls, and Risk.
* Audit and Security Events.

The logical model should remain independent of MongoDB or a relational database. MongoDB would provide persistence for the IAM Control Plane, storing identities, configurations, versioned policies, relationships, grants, lifecycle state, risks, evidence, and events. Runtime components — Identity Provider (IdP), Authorization Server (AS), Resource Server (RS), Policy Decision Point (PDP), Policy Enforcement Point (PEP), and PAM enforcement points — consume that state and apply decisions.

This position supports a MongoDB strategy without claiming that MongoDB replaces an IdP or a policy decision engine: MongoDB provides a flexible persistence layer for a heterogeneous, evolving, multi-tenant, relationship-oriented, event-driven security domain.

## 2. Architecture objectives

### 2.1. Functional objectives

The architecture should support:

* Registering human subjects, service accounts, workloads, devices, and agents.
* Integrating multiple identity sources and federated providers.
* Managing joiner-mover-leaver lifecycle processes.
* Modeling OAuth clients, relying parties, authorization servers, and resource servers.
* Representing scopes, claims, grants, roles, permissions, relationships, and contextual conditions.
* Resolving Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), and Relationship-Based Access Control (ReBAC), including hybrid models.
* Managing privileged access, just-in-time (JIT) elevations, approvals, and PAM sessions.
* Linking policies to controls, risks, exceptions, and evidence.
* Maintaining traceability for changes, decisions, and security events.
* Projecting the same logical model into SQL, MongoDB, or other stores.

### 2.2. Non-functional objectives

* Multi-tenancy and organizational isolation.
* Versioning of policies and configurations.
* Revocation and change propagation with controlled latency.
* Complete, tamper-resistant auditability.
* Schema evolution without breaking integrations.
* Support for human and non-human subjects.
* Structural and semantic data validation.
* Interoperability with relevant standards.
* Separation of authoritative data, derived projections, and events.

## 3. Design principles

### 3.1. Separate the logical and physical models

The logical model describes entities, relationships, invariants, and responsibilities. The physical model determines whether each entity is stored as a table, document, collection, index, event, or materialized projection.

This separation allows a normalized relational schema to serve as an integrity reference while read-optimized aggregates are implemented in MongoDB.

### 3.2. Separate the control plane, data plane, and event plane

The Control Plane maintains administrative and governance state: identities, policies, relationships, grants, configuration, and controls.

The Data Plane applies runtime decisions: authentication, token issuance, authorization, enforcement, privileged sessions, and access to resources.

The Event Plane distributes changes and preserves traceability: provisioning events, policy changes, access decisions, authentication events, and privilege elevations.

### 3.3. Distinguish identity, authentication, and authorization

* Identity answers “who or what is the subject?”
* Authentication answers “how was the subject verified?”
* Authorization answers “what may the subject do to which resource and under which context?”
* Governance answers “why does the subject have this access, who approved it, and when should it be reviewed?”
* Risk answers “what exposure does this access create and how is it treated?”

### 3.4. Use standards as profiles rather than as a monolithic model

System for Cross-domain Identity Management (SCIM), OAuth 2.0, OpenID Connect (OIDC), Financial-grade API (FAPI), AuthZEN, Open Security Controls Assessment Language (OSCAL), and Cloud Security Alliance Cloud Controls Matrix (CSA CCM) have different purposes. Each should be incorporated as a profile, interface, exchange format, or mapping — not as the entire enterprise model.

### 3.5. Separate policy from relationship data

A policy defines how access is interpreted. A relationship or entitlement represents the operational fact that a person, group, workload, or application has a relationship with a resource.

This separation is especially important for ReBAC/Zanzibar-style systems: the authorization schema defines the rules, while concrete relationships live as operational data.

### 3.6. Version and preserve critical records

Policies, critical decisions, privilege changes, and evidence should include a version, effective date, author, justification, and reference to the originating change.

## 4. Derived reference architecture

The following diagram is an implementation synthesis proposed in this document. It is not an official IDPro diagram; its purpose is to project IDPro and NIST concepts onto a MongoDB-optimized data and services architecture.

```text
Identity Sources
HR / Directory / Partners / Devices / Workloads
                         │
                         ▼
              IAM Control Plane
 ┌────────────────────────────────────────┐
 │ Identity Register                      │
 │ Lifecycle and Provisioning              │
 │ Federation and OAuth Configuration      │
 │ Entitlements and Authorization Graph    │
 │ Policy Administration                   │
 │ PAM Governance                          │
 │ Controls, Risk, and Evidence            │
 └──────────────────┬─────────────────────┘
                    │
                    │ Change events / projections
                    ▼
              Event Plane / Audit
                    │
       ┌────────────┼─────────────┐
       ▼            ▼             ▼
     IdP / AS       PDP           PAM
     Authentication  Authorization  Privileged Enforcement
       │            │             │
       └────────────┼─────────────┘
                    ▼
          Applications / Application Programming Interfaces (APIs) / Resources
```

### Correspondence between IDPro and the proposed implementation

| IDPro concept | Proposed logical projection | Suggested MongoDB projection |
|---|---|---|
| Identity Register | Canonical register of subjects and identifiers | `principals`, `identity_sources`, `identifiers`, or bounded embedded identifiers |
| Identity Management | Lifecycle, credentials, sources, metadata, and correlation | `principals`, `credential_references`, `identity_sources`, `lifecycle_events` |
| Identity Provider | Authentication, assertion, provisioning, session management, and metadata services | `identity_providers`, `applications`, `oauth_clients`, `key_sets` |
| Authentication and Assertion | Authentication evidence and result | `authentication_events`, `sessions`, credential references |
| Shared Authorization | Decisions, policies, roles, permissions, and relationships | `policies`, `policy_versions`, `relations`, `entitlements`, `authorization_decisions` |
| Local Authorization | Enforcement specific to each relying party or resource | `resources`, `actions`, `pep_bindings`, runtime projections |
| Access Governance | Requests, approvals, certifications, grants, and exceptions | `access_requests`, `approvals`, `elevation_grants`, `exceptions` |
| Audit Repository | Cross-cutting event and traceability record | `audit_events`, `change_events`, `authorization_decisions` |
| Metadata Management | Trust and interoperability data between components | `provider_metadata`, `trust_relationships`, `key_sets` |

The table preserves IDPro’s conceptual separation and adds a MongoDB storage projection. IDPro describes these components as conceptual groupings, not as a single physical system.

### 4.1. Identity Sources

Identity Sources provide identity attributes or state: HR, corporate directories, partners, customer identity systems, devices, cloud platforms, and workload runtimes.

A source should not automatically be treated as authoritative for every attribute. The model should record which source is authoritative for each attribute and which transformations are applied.

### 4.2. Identity Register

The Identity Register is the canonical register of subjects and identifiers. It should support human subjects, organizations, groups, service accounts, workloads, devices, and agents.

The [SCIM Core Schema, Request for Comments (RFC) 7643](https://www.rfc-editor.org/rfc/rfc7643.html) provides a platform-neutral schema for users, groups, and other resource types, together with an extension model. The [SCIM Protocol, RFC 7644](https://www.rfc-editor.org/info/rfc7644/) defines HTTP-based exchange. SCIM should be used as a provisioning contract, not as the complete authorization or PAM model.

### 4.3. Authentication and Federation

This bounded context maintains the configuration and state required to integrate IdPs, relying parties, authorization servers, and OAuth clients.

It should represent at least:

* Issuer and trust relationships.
* Discovery metadata.
* Authorization, token, userinfo, introspection, and revocation endpoints.
* JSON Web Key Set (JWKS) and key metadata.
* Clients, authentication methods, and redirect Uniform Resource Identifiers (URIs).
* Allowed grant types and scopes.
* Claims and attribute mappings.
* Assurance levels and multi-factor authentication (MFA) requirements.
* Lifetimes, refresh policies, and sender-constrained tokens.

The [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html) updates OAuth 2.0 security recommendations and deprecates insecure operating modes. For high-criticality Application Programming Interfaces (APIs), [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) defines a hardened profile based on OAuth 2.0, OIDC, Proof Key for Code Exchange (PKCE), Pushed Authorization Requests (PAR), and sender-constrained tokens.

### 4.4. Authorization and Entitlements

This bounded context represents authorization as a function of:

```text
Decision = f(Subject, Action, Resource, Context, Policy, Relationships)
```

The model should support three patterns:

* RBAC: a subject is assigned to a role and a role is associated with permissions.
* ABAC: a decision is based on subject, resource, action, and environment attributes.
* ReBAC: a decision is derived from relationships between subjects, groups, resources, and organizations.

The [Cloud Security Alliance IAM Standards guide](https://cloudsecurityalliance.org/artifacts/navigating-identity-and-access-management-iam) describes these models using users, roles, permissions, attributes, and relationships. Its ReBAC description uses graph entities and edges to express ownership, membership, management, and collaboration.

### 4.5. Policy Decision Point and Policy Enforcement Point

The PDP evaluates an authorization request. The PEP intercepts a request from an application, API, gateway, database, or service and applies the decision.

[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html) defines an interface for PEPs and PDPs to exchange requests and decisions without knowing each other’s internal details. The specification leaves the policy language, internal architecture, and PDP storage out of scope.

This allows an enterprise architecture to use:

* Open Policy Agent (OPA)/Rego for general policy-as-code and infrastructure controls.
* Cedar for declarative application authorization.
* OpenFGA, SpiceDB, or other Zanzibar-style engines for relationship-based authorization.
* eXtensible Access Control Markup Language (XACML) or other ABAC engines where there is a specific investment or requirement.

### 4.6. Privileged Access Management

PAM should be modeled as its own bounded context, while reusing subjects, resources, policies, and events from the wider IAM model.

Required entities include:

* PrivilegedAccount.
* TargetSystem.
* CredentialReference.
* SecretVault.
* AccessRequest.
* Approval.
* ElevationGrant.
* JITGrant.
* Session.
* CommandExecution.
* SessionRecording.
* RotationPolicy.
* BreakGlassEvent.

This separation prevents a permanent identity from being confused with a temporary elevation. A user may exist permanently, while authorization to access a production cluster as an administrator should be a temporary, justified, approved, and auditable grant.

### 4.7. Governance, Controls, and Risk

This domain connects authorization and technical controls with risk and compliance objectives.

[NIST OSCAL Layers and Models](https://pages.nist.gov/OSCAL/learn/concepts/layer/) provides models for catalogs, profiles, component definitions, system security plans, assessment plans, assessment results, and Plans of Action and Milestones (POA&M) in Extensible Markup Language (XML), JSON, and YAML.

The [CSA Cloud Controls Matrix and Consensus Assessments Initiative Questionnaire (CAIQ) v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) provides a cloud-control taxonomy and a machine-readable bundle in JSON, YAML, and OSCAL.

For enterprise risk, [NIST IR 8286 Rev. 1](https://csrc.nist.gov/pubs/ir/8286/r1/final) and [NIST IR 8286A Rev. 1](https://csrc.nist.gov/pubs/ir/8286/a/r1/final) provide guidance on cybersecurity risk registers, risk detail records, threat scenarios, likelihood, impact, treatment, ownership, and risk aggregation.

## 5. Canonical logical model

### 5.1. Identity entities

| Entity | Purpose | Suggested key attributes |
|---|---|---|
| Principal | General system subject | `principalId`, `tenantId`, `type`, `status`, `lifecycle` |
| Human | Person | `personName`, `employeeId`, `department`, `manager`, `employmentStatus` |
| ServiceAccount | Service identity | `owner`, `purpose`, `environment`, `rotationPolicy` |
| Workload | Service or process | `workloadId`, `trustDomain`, `runtime`, `attestation` |
| Agent | Automated agent identity | `owner`, `delegationChain`, `allowedTools` |
| Group | Set of subjects | `groupId`, `membershipPolicy`, `owner` |
| Organization | Organizational unit | `organizationId`, `parentOrganization` |
| Tenant | Isolation boundary | `tenantId`, `trustBoundary`, `dataResidency` |
| IdentitySource | Source system | `sourceId`, `type`, `authority`, `syncMode` |
| Identifier | External identifier | `sourceId`, `value`, `normalizedValue`, `verifiedAt` |
| CredentialReference | Reference to an authenticator | `credentialType`, `provider`, `status`, `lastUsedAt` |

### 5.2. Federation and OAuth/OIDC entities

| Entity | Purpose |
|---|---|
| IdentityProvider | Configuration for an internal or external IdP |
| RelyingParty | Application consuming federated authentication |
| OAuthClient | Client registered at an Authorization Server |
| AuthorizationServer | Token issuer and grant manager |
| ResourceServer | API or service protecting resources |
| ResourceIndicator | Token audience or target resource |
| Scope | Coarse-grained permission delegated to a client |
| ClaimMapping | Attribute-to-claim transformation |
| KeySet | Signing and verification keys |
| TokenPolicy | Time to live (TTL), audience, refresh, sender constraint, and revocation rules |
| ConsentGrant | Consent granted by a subject |

### 5.3. Authorization entities

| Entity | Purpose |
|---|---|
| Resource | Protected object: API, document, account, cluster, or secret |
| Action | Operation: read, write, approve, delete, administer |
| Role | Grouping of permissions or relationships |
| Permission | Concrete capability on a resource type |
| Entitlement | Access assignment to a subject |
| Relation | Subject-resource or resource-resource relationship |
| Policy | Declarative authorization rule |
| PolicyVersion | Immutable policy version |
| Condition | Attribute- or context-based condition |
| Decision | Evaluation result |
| Obligation | Mandatory action associated with a decision |
| PDP | Policy evaluation service |
| PEP | Component applying decisions |
| Policy Administration Point (PAP) | Policy administration service |
| Policy Information Point (PIP) | Provider of attributes used during evaluation |

### 5.4. PAM entities

| Entity | Purpose |
|---|---|
| PrivilegedAccount | Account with elevated privileges |
| TargetSystem | Server, database, cluster, or console target |
| SecretReference | Reference to an externally managed secret |
| AccessRequest | Privileged access request |
| Approval | Approval or rejection |
| ElevationGrant | Temporary privilege elevation |
| PrivilegedSession | Privileged session |
| CommandExecution | Commands or actions performed |
| RotationPolicy | Rotation and expiration rules |
| BreakGlassEvent | Exceptional emergency-access event |

### 5.5. Governance and risk entities

| Entity | Purpose |
|---|---|
| Framework | NIST, International Organization for Standardization (ISO), CSA CCM, or another framework |
| Control | Security or privacy control |
| Requirement | Concrete control requirement |
| Implementation | How a control is implemented |
| Assessment | Control assessment |
| Evidence | Verifiable evidence |
| Risk | Recorded risk |
| Threat | Threat event or actor |
| Vulnerability | Exploitable condition |
| Impact | Consequence for assets or objectives |
| Treatment | Accept, mitigate, transfer, or avoid |
| Exception | Approved exception |
| RiskOwner | Owner of the risk decision |

## 6. Essential relationships

```text
Principal ── belongs_to ── Tenant
Principal ── sourced_from ── IdentitySource
Principal ── member_of ── Group
Principal ── assigned ── Role
Role ── grants ── Permission
Principal ── has ── Entitlement
Principal ── relates_to ── Resource
Resource ── contains ── Resource
Policy ── evaluates ── Subject + Action + Resource + Context
Decision ── produced_by ── PDP
PEP ── enforces ── Decision
OAuthClient ── registered_at ── AuthorizationServer
AuthorizationServer ── issues ── Token
Token ── targets ── ResourceServer
PrivilegedAccount ── accesses ── TargetSystem
AccessRequest ── creates ── Approval
Approval ── enables ── ElevationGrant
ElevationGrant ── creates ── PrivilegedSession
Risk ── affects ── Resource / Policy / Control
Evidence ── supports ── Assessment / Control
```

## 7. Conceptual authorization representation

The following payload is not intended to replace AuthZEN or another protocol; it is an internal canonical representation:

```json
{
  "requestId": "req-123",
  "tenantId": "tenant-a",
  "subject": {
    "id": "user:antonio",
    "type": "human",
    "attributes": {
      "department": "industry-solutions",
      "assuranceLevel": "high"
    }
  },
  "action": {
    "name": "read",
    "resourceType": "security-policy"
  },
  "resource": {
    "id": "policy:prod-001",
    "type": "security-policy",
    "attributes": {
      "classification": "confidential",
      "owner": "team:security"
    }
  },
  "context": {
    "mfa": true,
    "deviceTrust": "managed",
    "sourceIpRisk": "low",
    "requestedAt": "2026-09-02T10:00:00Z"
  },
  "policyVersion": "policy-set-42"
}
```

A canonical response could contain:

```json
{
  "requestId": "req-123",
  "decision": "allow",
  "reasonCodes": ["ROLE_MATCH", "MFA_SATISFIED"],
  "obligations": [
    { "type": "AUDIT", "severity": "high" }
  ],
  "policy": {
    "policyId": "policy:security-read",
    "version": 7
  },
  "evaluatedAt": "2026-09-02T10:00:00Z"
}
```

## 8. Relational reference model

A SQL implementation could use the following tables:

```text
tenant
principal
human_profile
service_account
workload
identity_source
principal_identifier
credential_reference
group
membership
application
identity_provider
oauth_client
authorization_server
resource_server
resource
action
role
permission
role_assignment
entitlement
resource_relation
policy
policy_version
policy_condition
access_request
approval
elevation_grant
privileged_session
risk
control
assessment
evidence
audit_event
authorization_decision
```

Many-to-many relationships would be represented through association tables, for example:

```text
principal ──< role_assignment >── role
role ──< role_permission >── permission
principal ──< membership >── group
subject ──< resource_relation >── resource
policy_version ──< policy_condition
access_request ──< approval
control ──< evidence
risk ──< treatment
```

This relational model is an integrity and semantic reference. It does not require every runtime read to execute relational joins.

## 9. MongoDB physical projection

### 9.1. Recommended collections

```text
principals
identity_sources
applications
identity_providers
oauth_clients
authorization_servers
resource_servers
resources
actions
roles
permissions
entitlements
relations
policies
policy_versions
access_requests
approvals
elevation_grants
privileged_sessions
risks
controls
assessments
evidence
audit_events
authorization_decisions
```

### 9.2. Embedding

MongoDB recommends embedding when related data is queried together, belongs to a bounded aggregate, or must be updated atomically. See [Embedded Data Versus References - MongoDB Docs](https://www.mongodb.com/docs/upcoming/data-modeling/concepts/embedding-vs-references/).

Good embedding candidates include:

* Basic principal attributes.
* External identifiers for a principal when bounded.
* Lifecycle state.
* Metadata for a policy version.
* Small, bounded conditions.
* Static OAuth client configuration.
* A resource’s summary metadata.

Example:

```json
{
  "_id": "principal:123",
  "tenantId": "tenant-a",
  "type": "human",
  "identifiers": [
    {
      "sourceId": "idp:corporate",
      "value": "antonio@example.com",
      "verifiedAt": "2026-09-02T09:00:00Z"
    }
  ],
  "profile": {
    "displayName": "Antonio Membrides Espinosa",
    "department": "industry-solutions",
    "country": "ES"
  },
  "lifecycle": {
    "status": "active",
    "effectiveFrom": "2020-01-01T00:00:00Z",
    "effectiveTo": null
  },
  "assurance": {
    "level": "high",
    "lastVerifiedAt": "2026-09-02T09:00:00Z"
  },
  "schemaVersion": 1
}
```

### 9.3. Referencing

MongoDB recommends references for complex many-to-many relationships, high-cardinality data, large hierarchies, or entities queried independently. MongoDB provides `$lookup` and `$graphLookup` for referenced models. See [Reference Data in Your MongoDB Schema](https://www.mongodb.com/docs/manual/data-modeling/referencing/).

The following entities should normally remain in separate collections:

* Memberships and relationships.
* High-cardinality entitlements.
* Temporary grants.
* Privileged sessions.
* Audit events.
* Authorization decisions.
* Evidence and assessment results.
* Resources with unbounded growth.

Example relationship:

```json
{
  "_id": "relation:tenant-a:user-123:member:group-security",
  "tenantId": "tenant-a",
  "subject": {
    "type": "user",
    "id": "user-123"
  },
  "relation": "member",
  "object": {
    "type": "group",
    "id": "group-security"
  },
  "validity": {
    "from": "2026-01-01T00:00:00Z",
    "to": null
  },
  "source": "scim",
  "sourceVersion": "sync-991",
  "createdAt": "2026-09-02T09:00:00Z"
}
```

### 9.4. Versioned policy documents

Policies should be stored as immutable versions. A pointer or state document can indicate which version is active.

```json
{
  "policyId": "policy:security-read",
  "tenantId": "tenant-a",
  "version": 7,
  "status": "active",
  "effectiveFrom": "2026-09-01T00:00:00Z",
  "subject": {
    "roles": ["security-reader"]
  },
  "actions": ["read"],
  "resource": {
    "type": "security-policy"
  },
  "conditions": [
    {
      "attribute": "session.mfa",
      "operator": "equals",
      "value": true
    }
  ],
  "effect": "allow",
  "obligations": [
    { "type": "AUDIT", "severity": "high" }
  ],
  "approvedBy": "security-governance",
  "riskLinks": ["risk:stolen-session"],
  "createdAt": "2026-08-30T12:00:00Z"
}
```

### 9.5. Audit and decisions

Authorization decisions and security events should be kept in collections separate from operational state. This supports differentiated retention, archiving, searching, analysis, and access controls.

A decision should include:

* Request identifier.
* Subject, action, and resource.
* Allow/deny result.
* PDP and policy version.
* Reason codes.
* Relevant, minimized context.
* Timestamp and correlation identifier.
* PEP that applied the decision.
* Latency and dependency outcome.

### 9.6. Change Streams

[MongoDB Change Streams](https://www.mongodb.com/docs/manual/changeStreams/) allows applications to subscribe to changes in collections, databases, or deployments. In this architecture it can be used to:

* Propagate identity creation, deletion, and modification.
* Invalidate authorization caches.
* Trigger provisioning to applications.
* Recalculate exposure or risk.
* Record administrative changes.
* Notify revocations or policy changes.
* Feed audit and Security Information and Event Management (SIEM) pipelines.

Business events should include a correlation identifier and entity version to prevent out-of-order application of changes.

### 9.7. Atomicity and transactions

Operations affecting a single document are atomic. When a workflow modifies multiple documents — for example, closing an account, revoking entitlements, and recording an event — MongoDB provides distributed transactions for multi-document operations. See [Best Practices for Data Modeling in MongoDB](https://www.mongodb.com/docs/v7.1/data-modeling/concepts/embedding-vs-references/).

The recommendation is to design aggregates that minimize transactions and use transactions for genuinely cross-aggregate invariants.

### 9.8. Schema validation

The model should use schema validation to prevent incomplete or incompatible data. MongoDB allows validation rules to be applied only to the fields and structures that require stronger control. See [Data Modeling in MongoDB](https://www.mongodb.com/docs/manual/data-modeling/).

Example validation rules:

* `tenantId` is mandatory in all operational entities.
* `type` belongs to a controlled catalog.
* `status` belongs to an allowed state set.
* `validTo` is later than `validFrom`.
* `effect` is only `allow` or `deny`.
* `version` is positive and monotonic.
* `policyId` and `version` are unique together.
* `subject`, `relation`, and `object` are mandatory in relationship records.
* `decision` is mandatory in authorization decisions.
* `source` and `sourceVersion` are mandatory for synchronized data.

### 9.9. MongoDB design rules for the IAM profile

These rules are MongoDB implementation decisions and must not be confused with IDPro normative concepts:

* Keep `principals` as the canonical subject register; embedded role, group, or entitlement lists should be bounded read projections, not the authoritative source when they have high cardinality or an independent lifecycle.
* Keep `relations`, `memberships`, `entitlements`, `grants`, `sessions`, and `audit_events` in separate collections when they can grow without bound, are queried independently, or represent many-to-many relationships.
* Embed only data that belongs to the same aggregate, is read together, and has bounded growth. MongoDB documents that embedding can reduce queries and enable atomic updates within a document; it also documents a 16 MiB maximum document size. See [Embedded Data Versus References - MongoDB Docs](https://www.mongodb.com/docs/upcoming/data-modeling/concepts/embedding-vs-references/).
* Use references for hierarchies, memberships, and authorization relationships; resolve them with indexes designed for actual checks, and use `$lookup` or `$graphLookup` only when justified by the read pattern.
* Version policies immutably. A policy change should create a new version and change the active pointer in a controlled operation.
* Include `tenantId`, `schemaVersion`, `source`, `sourceVersion`, `createdAt`, and `updatedAt` where needed for isolation, evolution, and traceability.
* Apply schema validation to critical collections, especially identities, relationships, policies, grants, decisions, and events.
* Use transactions only for invariants that cross aggregates; do not turn every authorization check into a transaction.
* Use Change Streams for change propagation and cache invalidation, while preserving an explicit business event with correlation, version, and idempotency information.
* Store references to secrets and credentials managed by a vault or Hardware Security Module (HSM); do not turn the IAM database into a store of recoverable secrets.

## 10. Indexes and query patterns

Indexes should be derived from access patterns, not from entities in isolation.

### 10.1. Identity

```text
unique(tenantId, identitySourceId, normalizedIdentifier)
(tenantId, lifecycle.status)
(tenantId, type, lifecycle.status)
(profile.department, lifecycle.status)
```

### 10.2. Relationships and authorization

```text
(tenantId, object.type, object.id, relation)
(tenantId, subject.type, subject.id, relation)
(tenantId, subject.type, subject.id, object.type, object.id)
(tenantId, validFrom, validTo)
```

### 10.3. Policies

```text
unique(tenantId, policyId, version)
(tenantId, policyId, status)
(tenantId, effectiveFrom, effectiveTo)
```

### 10.4. Audit

```text
(tenantId, eventType, occurredAt)
(tenantId, subjectId, occurredAt)
(tenantId, resourceId, occurredAt)
(correlationId)
```

At scale, it is useful to separate runtime-read indexes from governance and audit indexes because they have different access patterns and retention requirements.

## 11. PAM-specific considerations

PAM should not be implemented only as an `isAdmin` field on a user. Privileged access requires an explicit chain:

```text
Principal
  → AccessRequest
  → Approval
  → ElevationGrant
  → PrivilegedSession
  → CommandExecution
  → SessionRecording
```

An `ElevationGrant` should include:

```json
{
  "grantId": "grant:987",
  "tenantId": "tenant-a",
  "principalId": "user:123",
  "targetId": "db:production",
  "privilege": "database-admin",
  "justification": "Incident INC-1234",
  "approvedBy": ["user:security-manager"],
  "validFrom": "2026-09-02T10:00:00Z",
  "validTo": "2026-09-02T12:00:00Z",
  "status": "active",
  "sessionId": "session:444"
}
```

The privileged account and the secret should be represented separately. The IAM system should store metadata, ownership, lifecycle, and vault references — not recoverable secrets in clear text.

## 12. Non-human identities and workloads

Modern IAM systems should explicitly model service accounts, workloads, pipelines, and agents. [An overview of the SPIFFE specification](https://spiffe.io/docs/latest/spiffe-about/overview/) defines an open framework for identifying workloads in heterogeneous environments through SPIFFE IDs and short-lived verifiable credentials called SPIFFE Verifiable Identity Documents (SVIDs).

SPIFFE provides identity but does not replace authorization. In the canonical model, a `Workload` can be a `Principal`, receive a SPIFFE identity, and subsequently be authorized through a policy, relationship, or entitlement.

## 13. Governance, controls, and risk

The relationship between IAM and risk should be explicit:

```text
Risk
 ├── affects → Resource
 ├── causedBy → Threat / Vulnerability
 ├── mitigatedBy → Control
 ├── treatedBy → Treatment
 ├── ownedBy → RiskOwner
 ├── linkedTo → Policy
 └── evidencedBy → Assessment / Evidence
```

Conceptual example:

```json
{
  "riskId": "risk:oauth-token-replay",
  "tenantId": "tenant-a",
  "category": "identity-and-access",
  "scenario": {
    "asset": "resource-server:payments",
    "threat": "stolen-access-token",
    "vulnerability": "bearer-token-replay",
    "impact": "unauthorized-sensitive-operation"
  },
  "likelihood": "medium",
  "impact": "high",
  "inherentRisk": "high",
  "controls": ["control:token-audience", "control:sender-constraint"],
  "treatment": "mitigate",
  "owner": "team:identity-security",
  "status": "open",
  "reviewAt": "2026-10-01T00:00:00Z"
}
```

OSCAL should be used for controls, implementation, assessments, and evidence when compliance interoperability is required. NIST IR 8286 should be used as a reference for risk structure and aggregation, not necessarily as the only operational format of the platform.

## 14. Architecture validation

### 14.1. Structural validation

* Validate each collection or table through JSON Schema, SQL schemas, or equivalent contracts.
* Validate catalogs of types, states, actions, and relationships.
* Validate uniqueness by tenant and identity source.
* Validate validity and expiration dates.
* Validate monotonic versioning.
* Validate that relationships do not cross incompatible tenants.

### 14.2. Semantic validation

* Every entitlement must reference a valid subject.
* Every permission must reference a valid action and resource type.
* Every privileged grant must have an owner, justification, and expiration.
* Every active policy must have an approved version.
* Every exception must have a risk owner and review date.
* Every evidence record must reference a control or assessment.
* Every decision must identify the PDP, policy, and minimum necessary context.

### 14.3. Interoperability validation

* Run SCIM provisioning tests.
* Validate OAuth/OIDC discovery and metadata.
* Run conformance tests for clients and authorization servers.
* Validate FAPI profiles when high-value APIs are involved.
* Validate the PEP-PDP interface through AuthZEN.
* Export controls and evidence in OSCAL.
* Maintain mappings between the internal catalog, CSA CCM, and other frameworks.

### 14.4. Policy validation

Each policy should have:

* Allowed cases.
* Denied cases.
* Boundary cases.
* Expiration tests.
* Revocation tests.
* Tenant-isolation tests.
* Policy-conflict tests.
* Missing-attribute tests.
* Fail-closed tests.
* Versioned regression history.

### 14.5. Operational validation

Measure at least:

* Provisioning and deprovisioning time.
* Revocation propagation time.
* p95 and p99 decision latency.
* Percentage of decisions using stale data.
* Privileged-session closure time.
* Policy-change propagation time.
* Number of orphaned identities.
* Number of expired, unrecovered grants.
* Number of expired exceptions.

## 15. How to support the MongoDB strategy

The architectural argument should be stated as follows:

MongoDB is appropriate as persistence for the IAM Control Plane when the system requires a heterogeneous, extensible, multi-tenant, relationship-oriented data model with multiple read patterns. MongoDB documentation describes a flexible model that supports polymorphic data, embedding, references, selective validation, and schema evolution. It also provides `$lookup` and `$graphLookup` for related data. See [Data Modeling in MongoDB](https://www.mongodb.com/docs/manual/data-modeling/) and [Embedded Data Versus References](https://www.mongodb.com/docs/upcoming/data-modeling/concepts/embedding-vs-references/).

The capabilities that align most closely are:

| IAM requirement | MongoDB capability | Rationale |
|---|---|---|
| Heterogeneous subjects | Polymorphic documents | Human, service account, workload, and agent can share a common core and extend it in a controlled way |
| Provider-specific IdP configuration | Documents with subdocuments | Providers can have different endpoints, claims, and capabilities |
| Relationships and entitlements | Referenced collections | Supports many-to-many relationships, hierarchies, and high cardinality |
| Versioned policies | Immutable documents | Supports versioning, approval, rollback, and traceability |
| Provisioning and lifecycle | Change Streams and transactions | Supports change propagation and coordinated multi-document updates |
| Audit | Append-oriented collections | Separates events and decisions from operational state |
| Standards evolution | Flexible schema with validation | Allows OAuth, FAPI, SCIM, and other profiles to evolve without redesigning every entity |
| Multi-tenancy | `tenantId` and compound indexes | Supports logical isolation and bounded queries |

These advantages do not mean that MongoDB is always superior to SQL. If the dominant workload requires complex analytical joins, strict referential integrity, and intensive relational reporting, SQL may be preferable. The decision should be based on access patterns, relationship volume, evolution requirements, and consistency requirements.

## 16. Boundaries and responsibilities

MongoDB should not be presented as a replacement for:

* An Identity Provider.
* An Authorization Server.
* A specialized Policy Decision Point.
* A PAM enforcement engine.
* A Hardware Security Module (HSM) or secrets vault.
* A SIEM.
* A complete risk-governance system.

MongoDB can provide the registry and persistence layer for configuration, relationships, policies, grants, risks, evidence, and events. Authentication, token issuance, policy evaluation, and enforcement should remain in specialized services or application components.

## 17. Implementation roadmap

### Phase 1: vocabulary and ownership

* Define the canonical glossary.
* Identify authoritative sources by attribute.
* Define tenants and trust boundaries.
* Define owners for identities, policies, resources, and risks.

### Phase 2: Identity Register

* Implement `Principal`, `IdentitySource`, `Identifier`, `Group`, and lifecycle.
* Add SCIM provisioning.
* Create deduplication and correlation rules.

### Phase 3: Federation and OAuth

* Model IdP, relying parties, clients, AS, RS, scopes, and claims.
* Add metadata and key sets.
* Validate the OAuth Security Best Current Practice (BCP).
* Apply FAPI to high-risk APIs.

### Phase 4: Authorization

* Define resources, actions, and permissions.
* Implement RBAC as a baseline.
* Add ABAC for context and attributes.
* Add ReBAC for hierarchies, ownership, and collaboration.
* Expose decisions through AuthZEN or an equivalent interface.

### Phase 5: PAM

* Register privileged accounts and targets.
* Implement requests, approvals, elevations, and sessions.
* Integrate vault, rotation, and recording.
* Add break-glass access and periodic reviews.

### Phase 6: Governance and Risk

* Map policies and resources to controls.
* Register evidence and assessments.
* Import and export OSCAL.
* Implement risk registers and treatment.

### Phase 7: Events and validation

* Enable Change Streams.
* Add an outbox or equivalent business-event mechanism.
* Implement decision and change auditing.
* Run conformance, security, performance, and recovery tests.

## 18. Conclusion

The recommended reference architecture is a layered IAM architecture based on:

* IDPro and NIST for conceptual architecture and vocabulary.
* SCIM for provisioning and lifecycle.
* OAuth/OIDC/FAPI for federation, clients, and tokens.
* AuthZEN for PEP-PDP interoperability.
* RBAC, ABAC, and ReBAC for authorization modeling.
* SPIFFE for workload identities.
* OSCAL and CSA CCM for controls, implementation, and evidence.
* NIST IR 8286 for risk registers and treatment.
* MongoDB as flexible persistence for the IAM Control Plane.

The strategic claim should not be that MongoDB implements all of IAM by itself. The stronger claim is that MongoDB can materialize a modern IAM logical model that combines polymorphic documents, relationships, versioned policies, events, audit, and governance data, while preserving a viable translation from a normalized relational design.

## 19. Bibliographic references

1. Cloud Security Alliance. (2026). [Identity and Access Management (IAM) Standards](https://cloudsecurityalliance.org/artifacts/navigating-identity-and-access-management-iam).
2. Cloud Security Alliance. (2026). [Cloud Controls Matrix and CAIQ v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1).
3. IDPro. Dobbs, G. B. (2021). [IAM Reference Architecture (v2)](https://bok.idpro.org/article/id/76/).
4. Internet Engineering Task Force. (2015). [RFC 7643: System for Cross-domain Identity Management: Core Schema](https://www.rfc-editor.org/rfc/rfc7643.html).
5. Internet Engineering Task Force. (2015). [RFC 7644: System for Cross-domain Identity Management: Protocol](https://www.rfc-editor.org/info/rfc7644/).
6. Internet Engineering Task Force. (2025). [RFC 9700: Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html).
7. National Institute of Standards and Technology. [Identity and Access Management NIST SP 1800-2 - NCCoE](https://www.nccoe.nist.gov/publication/1800-2/VolB/index.html).
8. National Institute of Standards and Technology. [Layers and Models - OSCAL](https://pages.nist.gov/OSCAL/learn/concepts/layer/).
9. National Institute of Standards and Technology. (2025). [IR 8286 Rev. 1, Integrating Cybersecurity and Enterprise Risk Management](https://csrc.nist.gov/pubs/ir/8286/r1/final).
10. National Institute of Standards and Technology. (2025). [IR 8286A Rev. 1, Identifying and Estimating Cybersecurity Risk for Enterprise Risk Management](https://csrc.nist.gov/pubs/ir/8286/a/r1/final).
11. OpenID Foundation. (2026). [AuthZEN](https://openid.net/wg/authzen/specifications/).
12. OpenID Foundation. (2026). [Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html).
13. OpenID Foundation. (2025). [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html).
14. OpenFGA. (2026). [Fine-Grained Authorization, ReBAC, ABAC & Zanzibar Explained](https://openfga.dev/docs/authorization-concepts).
15. SPIFFE. (2026). [An overview of the SPIFFE specification](https://spiffe.io/docs/latest/spiffe-about/overview/).
16. MongoDB. [Data Modeling in MongoDB](https://www.mongodb.com/docs/manual/data-modeling/).
17. MongoDB. [Embedded Data Versus References - Database Manual](https://www.mongodb.com/docs/upcoming/data-modeling/concepts/embedding-vs-references/).
18. MongoDB. [Reference Data in Your MongoDB Schema](https://www.mongodb.com/docs/manual/data-modeling/referencing/).
19. MongoDB. [MongoDB Change Streams](https://www.mongodb.com/docs/manual/changeStreams/).
20. MongoDB. [Best Practices for Data Modeling in MongoDB](https://www.mongodb.com/docs/v7.1/data-modeling/concepts/embedding-vs-references/).
