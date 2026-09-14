import { AppWindow, Eye, ShieldHalf, SlidersHorizontal, type LucideIcon } from 'lucide-react';

/**
 * What each role over this authority is FOR, written for a person.
 *
 * The authority itself is the source of truth for what a role may do; this file is the source of truth
 * for why. They are kept deliberately in step: every `can` line below corresponds to a permission the
 * seed actually grants over the authority's own resources, and every `cannot` line to one deliberately
 * withheld, because a reader who has just been refused something needs to know whether that was a
 * decision or a defect.
 *
 * Note what is absent: the roles that carry no authority permission at all. A customer, an analyst, an
 * investigator or a merchant officer administers nothing here, which is why they are described on the
 * overview as a group rather than given a page each.
 */

export interface RoleAbility {
  what: string;
  why: string;
}

export interface AuthorityRoleGuide {
  id: string;
  label: string;
  icon: LucideIcon;
  headline: string;
  who: string;
  /** Whether the role is native to the authority or an application role that also reaches in here. */
  origin: string;
  purpose: string;
  can: RoleAbility[];
  cannot: RoleAbility[];
  separation: string;
}

export const AUTHORITY_ROLE_GUIDE: AuthorityRoleGuide[] = [
  {
    id: 'realm_administrator',
    label: 'Realm administrator',
    icon: ShieldHalf,
    headline: 'Administers one authentication domain: its roles, its policies, its sessions and its signing keys.',
    who: 'Whoever this population already treats as the administrator of its realm.',
    origin: 'Native to the authority. It is not declared in any application catalog, because the objects it governs belong to no application.',
    purpose:
      'The role that shapes access itself. It composes roles, grants and withdraws them, writes the conditional statements evaluated after them, ends sessions, and holds custody of the keys the realm signs with.',
    can: [
      { what: 'Compose roles and read the permission catalog', why: 'A role is a named set of enforcement points that applications registered themselves. Composing one is administration; declaring one is the application’s job.' },
      { what: 'Grant and withdraw role assignments', why: 'Who holds what, which is the decision the whole system rests on.' },
      { what: 'Write and withdraw policies', why: 'Conditional statements evaluated after roles. A statement that denies is withdrawn by the same verb that adds one, so reading the rules and changing them are separate authorities.' },
      { what: 'End sessions', why: 'A compromised sign-in has to be stoppable without waiting for a token to expire.' },
      { what: 'Rotate a signing key, and retire one', why: 'Three different authorities on purpose. Reading a key set takes nothing away, rotating adds a key and takes nothing away, and retiring stops publication so every token already signed with it stops verifying.' },
    ],
    cannot: [
      { what: 'Read any application’s business data', why: 'This authority holds no accounts, no cards and no payments. There is nothing here to grant, which is the strongest form the separation can take.' },
      { what: 'Register principals or providers, on its own', why: 'Administering access is not the same standing as administering the directory. Those permissions are granted separately, so a realm can hand out one without the other.' },
      { what: 'Escape its own realm', why: 'Every permission is scoped to one realm. Reaching another requires an explicit cross-realm grant that is itself a record.' },
    ],
    separation:
      'Kept apart from the roles that administer an application’s own data, so administering identity is a distinct grant that can be reviewed and withdrawn on its own. It can grant itself more, which is exactly why every grant is written to the trail an auditor reads.',
  },
  {
    id: 'manager',
    label: 'Platform manager',
    icon: SlidersHorizontal,
    headline: 'Full platform administration, and no access to business or cardholder data.',
    who: 'The platform owner of the application realm.',
    origin: 'An application role that also carries permissions over the authority, because after the authority was extracted the objects it configures live here.',
    purpose:
      'Configures everything about how access works: realms, tenants, identity providers, principals, credentials, applications, roles, policies, sessions and grants, plus approving a request for temporary privilege.',
    can: [
      { what: 'Administer realms, tenants and identity providers', why: 'Where sign-in comes from and how the population is partitioned.' },
      { what: 'Administer principals and their credentials', why: 'The directory lifecycle: joining, changing, leaving.' },
      { what: 'Administer applications, and reissue a secret', why: 'Registering an application and reissuing its credential are separate actions, so they are separate permissions.' },
      { what: 'Administer roles, assignments, policies and the permission catalog', why: 'The whole access model, end to end.' },
      { what: 'Approve a request for temporary privilege', why: 'An elevation that nobody has to approve is not an elevation.' },
      { what: 'Read the signing keys', why: 'Sight of what the realm signs with, without custody of it.' },
    ],
    cannot: [
      { what: 'Read transactions, accounts or cardholder data', why: 'A platform administrator has no need for business data, and granting it would collapse the separation this role exists to maintain. The role that configures the platform cannot read what flows through it.' },
      { what: 'Rotate or retire a signing key', why: 'Custody of the keys is a different job from configuring the platform, and a role that could both register an application and reissue the keys that sign for it would have no independent check on either.' },
    ],
    separation:
      'The most powerful role on the platform and one of the ones with the least data. Configuration and content are held by different people on purpose.',
  },
  {
    id: 'security_auditor',
    label: 'Security auditor',
    icon: Eye,
    headline: 'Sees every object this authority holds, and can change none of them.',
    who: 'Internal audit, and whoever answers to the regulator.',
    origin: 'An application role carrying read permission over all fifteen of the authority’s own resources.',
    purpose:
      'Independent oversight of access itself. Realms, tenants, providers, principals, credentials, applications, roles, assignments, policies, the permission catalog, resource servers, sessions, grants, keys and elevations, all readable and none writable.',
    can: [
      { what: 'Read every one of the authority’s resources', why: 'Attesting to an access model means seeing all of it, not the part somebody chose to export.' },
      { what: 'Read who holds which role, and when it was granted', why: 'An assignment with no history is an assertion.' },
      { what: 'Read the identity trail', why: 'Who did what, when, and whether it succeeded.' },
      { what: 'Read sessions, grants and elevations', why: 'Standing access, delegated access and temporary access are three different questions.' },
    ],
    cannot: [
      { what: 'Change anything whatsoever', why: 'Read-only is the whole role. An auditor able to change what it audits cannot attest to it, so no permission here grants a mutation and none may be added without ending the role’s independence.' },
      { what: 'End a session or revoke a grant', why: 'Both are operational acts with a live effect on somebody’s access, and this role exists to review them.' },
    ],
    separation:
      'The widest read in the system paired with no write at all. That combination is what makes it safe to grant, and removing the second half would quietly remove the first half’s value.',
  },
  {
    id: 'client_administrator',
    label: 'Application administrator',
    icon: AppWindow,
    headline: 'Widens the application registry from what you own to the whole realm.',
    who: 'Whoever runs integrations for the realm.',
    origin: 'An application role with permissions over the authority’s registry, and none at all over the application.',
    purpose:
      'Registering an application needs no permission at all: a person owns what they register, and the registry narrows every read and every change to what they own. This role exists only to widen that narrowing.',
    can: [
      { what: 'Read and administer any application in the realm', why: 'Someone has to be able to fix a registration whose owner has left.' },
      { what: 'Reissue another party’s secret', why: 'A separate permission from reading their registration, because a role may hold sight of the registry without holding the ability to reissue anybody’s credential.' },
      { what: 'Read and administer principals', why: 'An integration is registered against a principal, so the two are administered together.' },
    ],
    cannot: [
      { what: 'Hold custody of signing keys', why: 'Key custody is a different job from administering the registry, and a role that could both register an application and reissue the keys that sign for it would have no independent check on either.' },
      { what: 'Reach any application data', why: 'The role has no permission over the application at all. It administers the registry and nothing behind it.' },
      { what: 'Compose roles or write policies', why: 'Registering who may ask is not deciding what they may have.' },
    ],
    separation:
      'A deliberately narrow widening. It removes the ownership filter on one registry and grants nothing else, which is the smallest role in the system and the clearest illustration of why permissions are pairs of resource and action rather than levels.',
  },
];

export function findAuthorityRole(id: string): AuthorityRoleGuide | undefined {
  return AUTHORITY_ROLE_GUIDE.find((role) => role.id === id);
}

/** The authority's own resources, and what may be done to each. Shown so a reader can see the shape. */
export const AUTHORITY_RESOURCES: Array<{ resource: string; actions: string[]; holds: string }> = [
  { resource: 'realms', actions: ['view', 'manage'], holds: 'A trust boundary: its issuer, its signing keys, its token lifetimes, its branding.' },
  { resource: 'tenants', actions: ['view', 'manage'], holds: 'A partition inside a realm.' },
  { resource: 'providers', actions: ['view', 'manage'], holds: 'An authentication domain: one way into a realm, its protocol and its rules for proving identity.' },
  { resource: 'identities', actions: ['view', 'manage'], holds: 'People, services and workloads, and their lifecycle.' },
  { resource: 'credentials', actions: ['view', 'manage'], holds: 'How a principal proves itself, including registered authenticators.' },
  { resource: 'clients', actions: ['view', 'manage', 'rotateSecret'], holds: 'Registered applications. Reissuing a secret is its own action.' },
  { resource: 'roles', actions: ['view', 'manage'], holds: 'Named sets of permissions.' },
  { resource: 'assignments', actions: ['view', 'manage'], holds: 'Who holds which role, in which scope.' },
  { resource: 'policies', actions: ['view', 'manage'], holds: 'Conditional statements evaluated after roles.' },
  { resource: 'permissions', actions: ['view', 'manage'], holds: 'The catalog of enforcement points applications register.' },
  { resource: 'resourceServers', actions: ['view', 'manage'], holds: 'The applications that declare and enforce those points.' },
  { resource: 'sessions', actions: ['view', 'manage'], holds: 'Where a principal is signed in.' },
  { resource: 'grants', actions: ['view', 'manage'], holds: 'What a principal allowed an application to do on its behalf.' },
  { resource: 'keys', actions: ['view', 'rotate', 'retire'], holds: 'What the realm signs with. Rotating adds; retiring stops verification.' },
  { resource: 'elevations', actions: ['view', 'approve', 'manage'], holds: 'Temporary authority, and the approval it waited for.' },
];
