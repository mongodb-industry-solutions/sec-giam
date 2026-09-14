import { Db } from 'mongodb';
import { RealmRecord } from '../../realm/models/realm.model';
import { RealmService } from '../../realm/services/realm.service';
import { DirectoryService } from '../../directory/services/directory.service';
import { activeHoldings, toScimEmails } from '../../directory/models/principal.model';
import { findOAuthClient } from '../../oauth/services/clientAuth.service';
import { ROLE_COLLECTION } from '../../../shared/models/collections';

/**
 * What the sign-in screen renders, built once per realm and asking client and then held briefly.
 *
 * This is the first thing an unauthenticated visitor loads, and building it reads the demo roster
 * out of an ENCRYPTED collection: every persona is decrypted before it can be listed, which is most
 * of the half second the screen used to wait for. The answer is also the same for everybody: it
 * carries branding, the domains and the demo personas, and nothing about who is asking beyond WHICH
 * APPLICATION asked.
 *
 * So it is cached on the pair that decides the answer: the realm, and the client whose `demoRoster`
 * says which roles that screen offers (`backend/data/clients.json`). Not on the URL, which is what
 * a browser cache would key on: a hosted sign-in arrives with a fresh `request_id` on every
 * redirect, so a URL-keyed cache never hits on the exact path the demonstration runs through, while
 * the many request ids of one booth session all resolve to a single client and a single roster.
 *
 * Held for seconds, not minutes, and deliberately with no invalidation to keep correct: a reseed
 * runs in a different process, so a roster changed underneath this one is picked up on the next
 * expiry rather than by a signal that would have to be delivered and could be missed. The runtime
 * reload clears it outright, which is the operator's way to see a change at once.
 */
const CACHE_TTL_MS = 30_000;

export interface RosterView {
  subjectId: string;
  userName: string;
  displayName?: string;
  email?: string;
  role?: string;
  demoNote?: string;
}

export interface LoginContextView {
  realm: string;
  displayName?: string;
  issuer?: string;
  notice?: string;
  registrationEnabled: boolean;
  branding: Record<string, unknown>;
  providers: Array<{ name: string; displayName: string; protocol: string; enabled: boolean; notice?: string }>;
  roster: RosterView[];
}

const cache = new Map<string, { expiresAt: number; view: LoginContextView }>();

/** Drops every held context. Called by the runtime reload, so a reseed is visible without a wait. */
export function forgetLoginContexts(): void {
  cache.clear();
}

export class LoginContextService {
  constructor(private readonly db: Db) {}

  /**
   * The context for this realm and this asking client, from the cache while it is still fresh.
   *
   * Says whether it was cached rather than logging it: a cache nobody can observe is a cache nobody
   * can rule out when a screen shows a persona that should no longer be there.
   */
  async read(realm: RealmRecord, askingClient?: string): Promise<{ view: LoginContextView; cached: boolean }> {
    const key = `${realm.realmId}|${askingClient ?? '-'}`;
    const now = Date.now();
    const held = cache.get(key);
    if (held && held.expiresAt > now) return { view: held.view, cached: true };

    const view = await this.build(realm, askingClient);
    cache.set(key, { expiresAt: now + CACHE_TTL_MS, view });
    // Expired entries are dropped on the way past rather than by a timer: realms times clients is a
    // small number, and a timer in a request path is a handle to leak.
    for (const [candidate, entry] of cache) if (entry.expiresAt <= now) cache.delete(candidate);
    return { view, cached: false };
  }

  private async build(realm: RealmRecord, askingClient?: string): Promise<LoginContextView> {
    const realmService = new RealmService(this.db);

    /**
     * Everything here is independent of everything else, so it is read at once rather than as a
     * waterfall: a chain of round trips that were never sequenced ON PURPOSE is exactly what turns
     * a small answer into a slow one.
     */
    const [providers, roster, joining, roles, client] = await Promise.all([
      realmService.providersFor(realm.realmId),
      new DirectoryService(this.db).demoRoster(realm.realmId),
      // Which path accepts joiners, resolved once for the response.
      realmService.registration(realm.realmId),
      this.db.collection(ROLE_COLLECTION)
        .find({ realmId: realm.realmId }, { projection: { _id: 0, roleId: 1, name: 1 } })
        .toArray() as unknown as Promise<Array<{ roleId: string; name: string }>>,
      // The roles this client's screen offers. Read from the client record rather than passed in,
      // so a caller cannot widen its own roster by asking for more.
      askingClient ? findOAuthClient(this.db, realm.realmId, askingClient) : Promise.resolve(null),
    ]);

    /**
     * The role a persona holds, resolved so the screen can offer one ready-made user per role. This
     * is the "one click per role" affordance the demonstration is built around.
     *
     * Read straight off `roster`, not a second principal query: `demoRoster()` already returns whole
     * principal documents, roles embedded and all. `activeHoldings` is the one place expiry and a
     * pending approval are already handled, so a lapsed or unapproved holding is excluded here
     * exactly as it would be anywhere else that asks what a subject holds now.
     */
    const roleNameById = new Map(roles.map((role) => [role.roleId, role.name]));

    // A persona can hold more than one role: the seed appends the realm administrator to whoever
    // already administers the realm. Collecting all of them, rather than keeping whichever the
    // driver returned last, is what stops those personas from being grouped under a role their
    // screen never offers and then filtered out of their own login list.
    const rolesBySubject = new Map<string, string[]>();
    for (const identity of roster) {
      for (const holding of activeHoldings(identity)) {
        const name = roleNameById.get(holding.roleId);
        if (!name) continue;
        const held = rolesBySubject.get(identity.subjectId);
        if (held) held.push(name);
        else rolesBySubject.set(identity.subjectId, [name]);
      }
    }

    const offered = client?.demoRoster;

    // The role this screen should show the persona under: the one it offers, when it offers any.
    const roleFor = (subjectId: string): string | undefined => {
      const held = rolesBySubject.get(subjectId) ?? [];
      return (offered && held.find((role) => offered.includes(role))) ?? held[0];
    };

    return {
      realm: realm.name,
      displayName: realm.displayName,
      issuer: realm.issuer,
      ...(realm.notice ? { notice: realm.notice } : {}),
      // Still one flag at the top level: a sign-in screen asks one question and should not have to
      // reason about which path answers it. Resolved from the internal path (ADR-002).
      registrationEnabled: joining.selfServiceEnabled,
      branding: realm.branding as unknown as Record<string, unknown>,
      providers: providers.map((provider) => ({
        name: provider.name,
        displayName: provider.displayName,
        protocol: provider.protocol,
        enabled: provider.enabled,
        ...(provider.notice ? { notice: provider.notice } : {}),
      })),
      roster: roster
        // An unknown client, or one that declares nothing, gets every featured persona: that is the
        // behaviour a realm with no application-specific screen should have.
        .filter((identity) => {
          if (!offered) return true;
          const role = roleFor(identity.subjectId);
          return Boolean(role && offered.includes(role));
        })
        .map((identity) => ({
          subjectId: identity.subjectId,
          // The login and the name are different things, and both are useful here: somebody
          // choosing a persona reads the name, and the field they then type is the login.
          userName: identity.userName,
          ...(identity.name?.formatted ? { displayName: identity.name.formatted } : {}),
          ...(toScimEmails(identity)[0] ? { email: toScimEmails(identity)[0].value } : {}),
          ...(roleFor(identity.subjectId) ? { role: roleFor(identity.subjectId) as string } : {}),
          ...(identity.demoNote ? { demoNote: identity.demoNote } : {}),
        })),
    };
  }
}
