import { NextRequest, NextResponse } from 'next/server';
import { SIMULATOR_REALM } from '../../../lib/constants';
import { API_PUBLIC_URL } from '../../../lib/env';

/**
 * The authorization endpoint's old address, kept working.
 *
 * When GIAM lived inside LeafyPay, an application started a flow at this console path and the page
 * here drove the protocol itself. Since v41 P4 the authority owns the flow and the endpoint is the
 * standard one, `/realms/{realm}/protocol/openid-connect/auth`. An integration written against the
 * old address would otherwise get a 404 before a single parameter was read, which tells whoever is
 * wiring it up nothing about what changed.
 *
 * So this forwards, and forwards VERBATIM: every parameter is carried across untouched, including
 * the optional prefill hints, because rewriting any of them here would mean this route deciding
 * something about a request that is the authority's to decide. The realm is the only addition, since
 * the old path had no room to name one.
 */
export function GET(request: NextRequest) {
  const incoming = request.nextUrl.searchParams;
  const realm = incoming.get('realm') || SIMULATOR_REALM;

  const target = new URL(`${API_PUBLIC_URL.replace(/\/$/, '')}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/auth`);
  for (const [key, value] of incoming.entries()) {
    if (key === 'realm') continue;
    target.searchParams.append(key, value);
  }

  // 302 rather than a permanent redirect: the old address is a compatibility shim, and a browser
  // that cached it permanently would keep using it after an integration had been updated.
  return NextResponse.redirect(target.toString(), 302);
}
