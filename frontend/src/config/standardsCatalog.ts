/**
 * The standards this authority speaks, and the ones it only takes into account.
 *
 * The distinction is the whole value of the list. A page that mixes "we implement this" with "we read
 * this and agreed with it" is a page that cannot be trusted on either, so `status` separates them and
 * nothing is listed as implemented unless a route or a service actually does it.
 */

export type StandardStatus = 'implemented' | 'partial' | 'considered';

export interface StandardEntry {
  /** The name a specialist would recognise, without the number in front of it. */
  name: string;
  /** The document, for a reader who wants to go and check. */
  reference: string;
  status: StandardStatus;
  /** What this authority actually does about it. */
  note: string;
}

export interface StandardGroup {
  group: string;
  intro: string;
  entries: StandardEntry[];
}

export const STANDARDS: StandardGroup[] = [
  {
    group: 'Authorization and tokens',
    intro:
      'The core of the authority. It issues tokens, and everything downstream verifies a signature and reads a claim rather than calling back here on every request.',
    entries: [
      {
        name: 'OAuth 2.0 Authorization Framework',
        reference: 'RFC 6749',
        status: 'implemented',
        note: 'Authorization code, client credentials and refresh token grants, with the authorization and token endpoints this realm advertises.',
      },
      {
        name: 'Proof Key for Code Exchange',
        reference: 'RFC 7636',
        status: 'implemented',
        note: 'Required, and only the hashed challenge is accepted. The plain method is in the specification and offers no protection at all, so it is not offered.',
      },
      {
        name: 'Token Introspection',
        reference: 'RFC 7662',
        status: 'implemented',
        note: 'A resource server that cannot verify locally can ask whether a token is still good.',
      },
      {
        name: 'Token Revocation',
        reference: 'RFC 7009',
        status: 'implemented',
        note: 'A token can be ended before it expires, which is what makes a compromise recoverable.',
      },
      {
        name: 'Token Exchange',
        reference: 'RFC 8693',
        status: 'implemented',
        note: 'Delegation and impersonation as distinct, recorded acts: acting with somebody’s authority is not the same as acting as them, and the token says which.',
      },
      {
        name: 'JWT Profile for OAuth 2.0 Access Tokens',
        reference: 'RFC 9068',
        status: 'implemented',
        note: 'Access tokens are structured so any resource server can read audience, subject and permissions the same way.',
      },
      {
        name: 'JSON Web Key and JWK Thumbprint',
        reference: 'RFC 7517, RFC 7638',
        status: 'implemented',
        note: 'The published key set, with each key identified by a thumbprint of its own material rather than by a name somebody chose.',
      },
      {
        name: 'OAuth 2.0 Security Best Current Practice',
        reference: 'RFC 9700',
        status: 'considered',
        note: 'Read as guidance and reflected in the choices above, notably the mandatory hashed challenge and the refusal of implicit flows.',
      },
      {
        name: 'Demonstrating Proof of Possession',
        reference: 'DPoP, RFC 9449',
        status: 'considered',
        note: 'Not implemented. Binding a token to a key would narrow what a stolen bearer token is worth, and it is the clearest next step here.',
      },
    ],
  },
  {
    group: 'Authentication and federation',
    intro: 'How a principal proves who it is, and how another authority is trusted to say so.',
    entries: [
      {
        name: 'OpenID Connect Core',
        reference: 'OIDC Core 1.0',
        status: 'implemented',
        note: 'Identity tokens, the user information endpoint and sign-out, signed with a rotating realm key.',
      },
      {
        name: 'OpenID Connect Discovery and Authorization Server Metadata',
        reference: 'OIDC Discovery 1.0, RFC 8414',
        status: 'implemented',
        note: 'One well-known document per realm, so a client configures itself from the issuer instead of from a runbook.',
      },
      {
        name: 'Client-Initiated Backchannel Authentication',
        reference: 'OIDC CIBA 1.0',
        status: 'implemented',
        note: 'Passwordless sign-in approved on a device the person already holds. The browser asking never sees a credential, which is what makes it phishing-resistant.',
      },
      {
        name: 'Mutual TLS client authentication',
        reference: 'RFC 8705',
        status: 'partial',
        note: 'Modelled on the client record but not live. The methods this realm advertises are the secret-based ones and none.',
      },
    ],
  },
  {
    group: 'Provisioning, registration and interfaces',
    intro: 'How principals and applications arrive, and how the API behaves when something goes wrong.',
    entries: [
      {
        name: 'System for Cross-domain Identity Management',
        reference: 'SCIM 2.0, RFC 7643, RFC 7644',
        status: 'implemented',
        note: 'The directory speaks the provisioning protocol, so joining, changing and leaving arrive from an external source of truth rather than from a script.',
      },
      {
        name: 'Dynamic Client Registration and Management',
        reference: 'RFC 7591, RFC 7592',
        status: 'implemented',
        note: 'An application registers itself and manages its own record afterwards, narrowed to what it owns.',
      },
      {
        name: 'Problem Details for HTTP APIs',
        reference: 'RFC 9457',
        status: 'implemented',
        note: 'Every failure answers in the same shape, so a caller handles errors rather than parsing prose.',
      },
      {
        name: 'OpenAPI',
        reference: 'OpenAPI 3',
        status: 'implemented',
        note: 'The whole surface is described, and where a route has no governing standard its description says so in those words, so a bespoke endpoint and a conforming one are never mistaken for each other.',
      },
    ],
  },
  {
    group: 'Regulation and control frameworks taken into account',
    intro:
      'This authority implements none of these itself. It holds no accounts, no cards and no payments, so what it does is carry the obligations of the institutions around it.',
    entries: [
      {
        name: 'Payment services rules on strong customer authentication',
        reference: 'PSD2 and the technical standard on authentication',
        status: 'considered',
        note: 'Backchannel authentication on a registered device provides the possession and the dynamic linking an institution needs. Account-access consent stays with the institution holding the account, because that is regulated business data and it does not belong here.',
      },
      {
        name: 'Data protection rules',
        reference: 'GDPR',
        status: 'considered',
        note: 'Minimisation in what a token carries, encryption of personal data at rest, a lifecycle that supports erasure, and a trail that records who read what.',
      },
      {
        name: 'Card security rules',
        reference: 'PCI DSS',
        status: 'considered',
        note: 'No cardholder data reaches this authority by design, which is the cheapest way to satisfy a regime: stay out of its scope. What it contributes is the identity, the least-privilege role model and the audit trail those rules require of the systems that are in scope.',
      },
      {
        name: 'Financial-grade API profile',
        reference: 'FAPI 2.0',
        status: 'considered',
        note: 'Read as the target for a hardened deployment. Sender-constrained tokens and mutual TLS are the gap between here and there.',
      },
      {
        name: 'Identity and access management guidance',
        reference: 'NIST digital identity guidelines',
        status: 'considered',
        note: 'Informs the separation of duties in the role model and the treatment of an authenticator as a distinct, revocable object.',
      },
    ],
  },
];

export const STATUS_LABEL: Record<StandardStatus, string> = {
  implemented: 'Implemented',
  partial: 'Partial',
  considered: 'Taken into account',
};

export const STATUS_STYLE: Record<StandardStatus, string> = {
  implemented: 'border-[#00ED64]/40 bg-[#00ED64]/10 text-[#00684A]',
  partial: 'border-amber-300 bg-amber-50 text-amber-700',
  considered: 'border-gray-200 bg-gray-50 text-gray-600',
};
