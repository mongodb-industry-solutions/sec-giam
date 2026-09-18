import { Db } from 'mongodb';
import type { OAuthErrorCode } from '../../../shared/models/problem';
import { RealmRecord } from '../../realm/models/realm.model';
import { OAuthClient } from '../models/client.model';
import { DirectoryService } from '../../directory/services/directory.service';
import { DecisionService } from '../../authorization/services/decision.service';
import { SecurityEventService } from '../../audit/services/securityEvent.service';
import { PrincipalRecord, canAuthenticate } from '../../directory/models/principal.model';
import { ActorClaim } from '../models/actor.model';

/**
 * Token exchange: acting as somebody else, on the record.
 *
 * The point of doing this properly rather than with a shared password is the `act` claim. A token
 * obtained here says "the simulator, acting as this person", so every action it takes is attributable
 * to BOTH. A shared demo credential produces a token indistinguishable from the person's own, which
 * means the audit trail cannot tell you whether they did something or something did it as them.
 *
 * Two paths in, checked in this order, each closing a different way this could become a way in:
 *
 * 1. BUSINESS (ADR-004). The client's own credential holds `subjects:actAs` at the ONE audience it
 *    is registered for, checked at the same decision point as every other permission. No realm mode
 *    and no persona restriction: this is the path a real application uses to act for a real person
 *    it never received a token from, and restricting it to demo personas would make it useless for
 *    that. Declared as an ordinary permission on the requesting resource server, never under
 *    `authority`, so holding it never reaches beyond the one application it was granted for.
 * 2. DEMO IMPERSONATION, unchanged from before ADR-004. Three bounds:
 *    a. The realm must permit it. A realm that is not a demonstration cannot issue one at all, so the
 *       capability cannot be turned on against real people by configuring a client.
 *    b. The subject must be one of the realm's declared demo personas. Holding the client credential
 *       does not let its holder become an arbitrary principal.
 *    c. The client must hold `impersonation:exercise` at the `authority` audience. This is the
 *       simulator's own persona switcher and stays exactly as narrow as it always was.
 */

export const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/** The resource server the authority registers its OWN permissions under. */
const AUTHORITY_AUDIENCE = 'authority';

export interface ExchangeRefusal {
  status: number;
  /** Typed to the closed RFC 6749 set, so a code a client cannot switch on will not compile. */
  error: OAuthErrorCode;
  description?: string;
}

export interface ExchangeSubject {
  identity: PrincipalRecord;
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
    client: OAuthClient,
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

    // Common to both paths: the target has to be a real, live principal in THIS realm before either
    // path is even worth asking about. Neither path may act as somebody who could not sign in.
    const directory = new DirectoryService(this.db);
    const identity = await directory.findByLogin(realm.realmId, requested.subject)
      ?? await directory.findBySubjectId(requested.subject);
    if (!identity || identity.realmId !== realm.realmId) return refuse('unknown_subject');
    if (!canAuthenticate(identity)) return refuse('subject_cannot_authenticate');

    const succeed = (via: string): ExchangeSubject => {
      void new SecurityEventService(this.db).record({
        realmId: realm.realmId,
        tenantId: realm.tenantId,
        category: 'authorization',
        action: 'token.exchange',
        outcome: 'success',
        clientId: client.clientId,
        subjectId: identity.subjectId,
        detail: { actingAs: identity.userName, via },
      });
      // Carried into the token, so the trail reads "leafypay-backend acting as this buyer" rather
      // than just "this buyer". That is strictly better evidence than the flow it replaces.
      return { identity, actor: { sub: client.clientId, client_id: client.clientId } };
    };

    /**
     * ADR-004: the BUSINESS path.
     *
     * Scoped to the ONE audience this client is itself registered for: `subjects:actAs` at that
     * audience is what says "this application may act for a person AT ITSELF", not "this
     * application may act for a person anywhere". A client declaring no audience, or more than one,
     * has no single audience this can mean, and falls through to the demo path unaffected rather
     * than being guessed at.
     */
    const [soleAudience, ...rest] = client.audience ?? [];
    if (soleAudience && rest.length === 0) {
      const business = await new DecisionService(this.db)
        .check(realm.realmId, client.clientId, soleAudience, 'subjects', 'actAs', client.credentialId);
      if (business.effect === 'allow') return succeed('subjects:actAs');
    }

    // DEMO IMPERSONATION, unchanged. A realm that is not a demonstration cannot impersonate at all,
    // which is the bound that makes the capability safe to ship enabled: it is off wherever it would
    // matter.
    if (!realm.demoMode) return refuse('realm_does_not_permit_impersonation');

    // Only a declared demo persona. Holding the client secret is not the same as being allowed to
    // become anyone, which is precisely the difference between this and a shared password.
    if (!identity.demoFeatured) return refuse('subject_is_not_a_demo_persona');

    // Asked against the AUTHORITY's own resource server, not the client's. Permissions are scoped by
    // audience, and impersonation is a permission over this service rather than over the application
    // the client normally calls, so checking it under the client's audience would never find it.
    const decision = await new DecisionService(this.db)
      .check(realm.realmId, client.clientId, AUTHORITY_AUDIENCE, 'impersonation', 'exercise');
    if (decision.effect !== 'allow') return refuse('client_lacks_impersonation_permission');

    return succeed('impersonation:exercise');
  }
}
