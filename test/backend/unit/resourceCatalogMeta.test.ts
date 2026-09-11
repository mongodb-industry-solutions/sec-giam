// `resources.json` describes every resource the seeder writes, per realm, with nothing missing.
//
// A resource type is created from the permission keys in the role fixtures, while what it is CALLED
// and what it MEANS come from `resources.json`. Nothing in the seeder connects the two: granting a
// permission over a new resource type seeds the type happily and leaves it with no label, so the
// console shows a bare `investmentPortfolios` and a reader has nothing to go on. That is invisible
// in a diff, and it is how the catalog looked before this was asserted.
//
// Keyed by REALM throughout, because that is the correction this fixture exists for: the labels used
// to be a map keyed by type name alone, so two realms declaring a resource of the same name could
// not describe it differently and the last one to load won.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

interface ResourceServerFixture {
  realm: string;
  name: string;
  audience: string;
  displayName: string;
  description: string;
  resources: Array<{ name: string; displayName: string; description: string }>;
}

interface RoleFixture {
  realm: string;
  resourceServer: string;
  permissions?: Record<string, string[]>;
  authorityPermissions?: Record<string, string[]>;
}

const data = (file: string) => JSON.parse(readFileSync(resolve(__dirname, '../../../backend/data', file), 'utf8'));

/**
 * A client's SERVICE IDENTITY grants permissions too, and it is the half that was missed.
 *
 * `psd2Role` and `impersonation` reach the catalog only through `clients.json`, so a check that
 * read the role fixtures alone called the catalog fully described while two resource types sat in
 * the database with no name and no description. Both sources are read here for that reason.
 */
interface ClientFixture {
  realm: string;
  serviceIdentity?: { resourceServer?: string; permissions?: Record<string, string[]> };
}

const servers = data('resources.json') as ResourceServerFixture[];
const roles = [...data('roles.json'), ...data('bankRoles.json')] as RoleFixture[];
const clients = data('clients.json') as ClientFixture[];

/** `realm|server|type` for every resource type anything in the fixtures grants a permission over. */
const declaredByRoles = new Set<string>();
for (const role of roles) {
  for (const type of Object.keys(role.permissions ?? {})) {
    declaredByRoles.add(`${role.realm}|${role.resourceServer}|${type}`);
  }
  for (const type of Object.keys(role.authorityPermissions ?? {})) {
    declaredByRoles.add(`${role.realm}|authority|${type}`);
  }
}
for (const client of clients) {
  const identity = client.serviceIdentity;
  if (!identity?.resourceServer) continue;
  for (const type of Object.keys(identity.permissions ?? {})) {
    declaredByRoles.add(`${client.realm}|${identity.resourceServer}|${type}`);
  }
}

const described = new Set(servers.flatMap((server) => server.resources.map((r) => `${server.realm}|${server.name}|${r.name}`)));

const blank = (value: string | undefined) => !value || !value.trim();

describe('resources.json describes the catalog the seeder writes', () => {
  it('declares resource servers and types at all, so the assertions below mean something', () => {
    expect(servers.length).toBeGreaterThan(0);
    expect(declaredByRoles.size).toBeGreaterThan(0);
  });

  it('names a realm on every resource server, so no configuration floats free of one', () => {
    const unscoped = servers.filter((server) => blank(server.realm)).map((server) => server.name);
    expect(unscoped, `resource servers with no realm: ${unscoped.join(', ')}`).toEqual([]);
  });

  it('gives every resource server a display name, a description and an audience', () => {
    const incomplete = servers
      .filter((server) => blank(server.displayName) || blank(server.description) || blank(server.audience))
      .map((server) => `${server.realm}/${server.name}`);
    expect(incomplete, `resource servers missing a label: ${incomplete.join(', ')}`).toEqual([]);
  });

  it('gives every resource type a display name and a description', () => {
    const incomplete = servers.flatMap((server) => server.resources
      .filter((entry) => blank(entry.displayName) || blank(entry.description))
      .map((entry) => `${server.realm}/${server.name}/${entry.name}`));
    expect(incomplete, `resource types missing a label: ${incomplete.join(', ')}`).toEqual([]);
  });

  /** The gap that matters: a role grants it, so the seeder creates it, and nothing describes it. */
  it('describes every resource type a role actually grants', () => {
    const undescribed = [...declaredByRoles].filter((key) => !described.has(key)).sort();
    expect(
      undescribed,
      `granted by a role but absent from resources.json, so it would be seeded unlabelled: ${undescribed.join(', ')}`,
    ).toEqual([]);
  });

  /** The reverse gap: a description for something nothing grants is a rename left half done. */
  it('describes no resource type that no role grants', () => {
    const orphaned = [...described].filter((key) => !declaredByRoles.has(key)).sort();
    expect(orphaned, `described in resources.json but granted by no role: ${orphaned.join(', ')}`).toEqual([]);
  });

  it('names each resource type once per resource server', () => {
    const duplicated = servers.flatMap((server) => {
      const seen = new Map<string, number>();
      for (const entry of server.resources) seen.set(entry.name, (seen.get(entry.name) ?? 0) + 1);
      return [...seen.entries()].filter(([, n]) => n > 1).map(([name]) => `${server.realm}/${server.name}/${name}`);
    });
    expect(duplicated).toEqual([]);
  });
});
