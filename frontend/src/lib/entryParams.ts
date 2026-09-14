'use client';

/**
 * The defaults an entry URL may carry: which realm, which authentication domain, who.
 *
 * Two screens are entry points into this product (`/system`, and the hosted sign-in at
 * `/auth/login`) and both were reachable only at their bare address, which meant a demonstration
 * that wanted to start on a federated path had to click through to it, and an integrator linking
 * to a specific realm had no way to say so. These read the same parameters, with the same names,
 * for the same reason: an entry point should be linkable to the state you want it to open in.
 *
 * PRESENTATION ONLY, and that is the boundary. They decide what a field or a picker starts out
 * holding. Nothing here is carried into the authorization request, whose parameters are read back
 * from the stored ticket by the authority; nothing here widens what a caller may do, and the domain
 * a credential actually belongs to is still resolved server side no matter what was picked.
 *
 * Two spellings are accepted for the realm (`realm`, `kc_realm`) and two for the domain
 * (`domain`, `kc_idp_hint`), because the second of each is what an application already emitting
 * these links is likely to be sending. `login_hint` is the OIDC parameter and needs no alias.
 */

export interface EntryDefaults {
  /** The realm to act on or sign in against. Absent means the caller's remembered one. */
  realm?: string;
  /** The authentication domain to preselect in the picker, by slug. */
  domain?: string;
  /** What the login field starts out holding, per OIDC `login_hint`. */
  login?: string;
}

/** Reads them from a query string. Blank values are treated as absent, never as an empty choice. */
export function readEntryDefaults(search: string): EntryDefaults {
  const params = new URLSearchParams(search);
  const first = (...names: string[]): string | undefined => {
    for (const name of names) {
      const value = params.get(name)?.trim();
      if (value) return value;
    }
    return undefined;
  };
  return {
    ...(first('realm', 'kc_realm') ? { realm: first('realm', 'kc_realm') } : {}),
    ...(first('domain', 'kc_idp_hint') ? { domain: first('domain', 'kc_idp_hint') } : {}),
    ...(first('login_hint') ? { login: first('login_hint') } : {}),
  };
}
