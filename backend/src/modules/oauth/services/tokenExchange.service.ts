import { Db } from 'mongodb';
import { RealmRecord } from '../../realm/models/realm.model';
import { ClientRecord } from '../models/client.model';
import { DirectoryService } from '../../directory/services/directory.service';
import { DecisionService } from '../../authorization/services/decision.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { IdentityRecord, canAuthenticate } from '../../directory/models/identity.model';
import { ActorClaim } from '../models/token.model';

/**
 * Token exchange: acting as somebody else, on the record.
 *
 * The point of doing this properly rather than with a shared password is the `act` claim. A token
 * obtained here says "the simulator, acting as this person", so every action it takes is attributable
 * to BOTH. A shared demo credential produces a token indistinguishable from the person's own, which
 * means the audit trail cannot tell you whether they did something or something did it as them.
 *
 * Three bounds, each closing a different way this could become a way in:
 *
 * 1. The realm must permit it. A realm that is not a demonstration cannot issue one at all, so the
 *    capability cannot be turned on against real people by configuring a client.
 * 2. The subject must be one of the realm's declared demo personas. Holding the client credential
 *    does not let its holder become an arbitrary principal.
 * 3. The client must hold the permission. It is checked at the same decision point as everything
 *    else rather than being implied by owning a secret.
 */

export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/** The resource server the authority registers its OWN permissions under. */
const AUTHORITY_AUDIENCE = 'authority';

export interface ExchangeRefusal {
  status: number;
  error: string;
  description?: string;
}

export interface ExchangeSubject {
  identity: IdentityRecord;
  actor: ActorClaim;
}

export function isRefusal(value: unknown): value is ExchangeRefusal {
  return typeof value === 'object' && value !== null && 'error' in value && 'status' in value;
}

export class TokenExchangeService {
  constructor(private readonly db: Db) {}

  /**
   * Resolves who the caller may act as, or why not.
   *
   * Every refusal is the same code and a vague description. A token endpoint that explains precisely
   * which of the three bounds stopped it is a probe for finding out which principals are demo
   * personas, and the caller cannot act on the difference anyway.
   */
  async resolve(
    realm: RealmRecord,
    client: ClientRecord,
    requested: { subjectToken?: string; subject?: string; subjectTokenType?: string },
  ): Promise<ExchangeSubject | ExchangeRefusal> {
    const refuse = (cause: string): ExchangeRefusal => {
      void new SecurityEventService(this.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authorization',
        action: 'token.exchange',
        outcome: 'failure',
        clientId: client.clientId,
        cause,
        detail: { requestedSubject: requested.subject },
      });
      return { status: 400, error: 'invalid_request', description: 'That exchange is not permitted.' };
    };

    if (requested.subjectTokenType && requested.subjectTokenType !== ACCESS_TOKEN_TYPE) {
      return refuse('unsupported_subject_token_type');
    }
    if (!requested.subject) return refuse('no_subject_requested');

    // A realm that is not a demonstration cannot impersonate at all. This is the bound that makes
    // the capability safe to ship enabled: it is off wherever it would matter.
    if (!realm.demoMode) return refuse('realm_does_not_permit_impersonation');

    const directory = new DirectoryService(this.db);
    const identity = await directory.findByLogin(realm.realmId, requested.subject)
      ?? await directory.findBySubjectId(requested.subject);
    if (!identity || identity.realmId !== realm.realmId) return refuse('unknown_subject');
    if (!canAuthenticate(identity)) return refuse('subject_cannot_authenticate');

    // Only a declared demo persona. Holding the client secret is not the same as being allowed to
    // become anyone, which is precisely the difference between this and a shared password.
    if (!identity.demoFeatured) return refuse('subject_is_not_a_demo_persona');

    // Asked against the AUTHORITY's own resource server, not the client's. Permissions are scoped by
    // audience, and impersonation is a permission over this service rather than over the application
    // the client normally calls, so checking it under the client's audience would never find it.
    const decision = await new DecisionService(this.db)
      .check(realm.realmId, client.clientId, AUTHORITY_AUDIENCE, 'impersonation', 'exercise');
    if (decision.effect !== 'allow') return refuse('client_lacks_impersonation_permission');

    void new SecurityEventService(this.db).record({
      realmId: realm.realmId,
      tenantId: realm.tenantId,
      category: 'authorization',
      action: 'token.exchange',
      outcome: 'success',
      clientId: client.clientId,
      subjectId: identity.subjectId,
      detail: { actingAs: identity.userName },
    });

    // Carried into the token, so the trail reads "the simulator acting as Julia Santos" rather than
    // "Julia Santos". That is strictly better evidence than the flow it replaces.
    return { identity, actor: { subjectId: client.clientId, clientId: client.clientId } };
  }
}
