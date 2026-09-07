// v41 P2: the error code a client switches on is chosen, not derived.
//
// The defect this replaces was structural rather than a wrong value somewhere. `oauthError` computed
// the code from the HTTP status, so the whole surface could only ever emit four of the RFC's codes,
// and the authorization endpoint reached the client as `invalid_request` however precisely it had
// determined the cause. A client cannot distinguish "your code expired" from "your request was
// malformed" when both arrive as `invalid_request`.
//
// So what is asserted here is the SET: every code the specifications define for these endpoints is
// expressible, and nothing outside the set is.
import { describe, it, expect } from 'vitest';
import { oauthError, oauthErrorForStatus } from '../../../backend/src/shared/models/problem';
import type { OAuthErrorCode } from '../../../backend/src/shared/models/problem';

describe('v41 P2: the code is an argument, and the status no longer decides it', () => {
  it('emits the code it was given, whatever the status', () => {
    expect(oauthError('invalid_grant', 'code is expired')).toEqual({
      error: 'invalid_grant',
      error_description: 'code is expired',
    });
    // Same status, four different codes. Under the previous helper all four were invalid_request.
    for (const code of ['invalid_grant', 'invalid_scope', 'unsupported_grant_type', 'unauthorized_client'] as const) {
      expect(oauthError(code, 'x', 400).error).toBe(code);
    }
  });

  it('suppresses the description on a server error, because that message is not for a caller', () => {
    expect(oauthError('server_error', 'ECONNREFUSED 127.0.0.1:27017', 500)).toEqual({ error: 'server_error' });
    expect(oauthError('server_error', 'internal', 503)).toEqual({ error: 'server_error' });
  });

  /**
   * The one place that genuinely has only a status is the error handler, which catches a thrown
   * failure or a schema rejection where no call site chose a code. Kept as its own function so a
   * controller cannot reach it by omission.
   */
  it('derives a code from a status only where nothing better is known', () => {
    expect(oauthErrorForStatus(401)).toBe('invalid_client');
    expect(oauthErrorForStatus(403)).toBe('access_denied');
    expect(oauthErrorForStatus(400)).toBe('invalid_request');
    expect(oauthErrorForStatus(500)).toBe('server_error');
    expect(oauthErrorForStatus(503)).toBe('server_error');
  });
});

describe('v41 P2: the set is closed, and covers every code these endpoints need', () => {
  it('expresses every RFC 6749 code for both endpoints', () => {
    // 5.2, the token endpoint.
    const tokenEndpoint: OAuthErrorCode[] = [
      'invalid_request', 'invalid_client', 'invalid_grant',
      'unauthorized_client', 'unsupported_grant_type', 'invalid_scope',
    ];
    // 4.1.2.1, the authorization endpoint.
    const authorizationEndpoint: OAuthErrorCode[] = [
      'invalid_request', 'unauthorized_client', 'access_denied', 'unsupported_response_type',
      'invalid_scope', 'server_error', 'temporarily_unavailable',
    ];
    for (const code of [...tokenEndpoint, ...authorizationEndpoint]) {
      expect(oauthError(code).error).toBe(code);
    }
  });

  /**
   * The backchannel codes are in the set because typing it closed rejected them, which is the check
   * doing its job: they were being emitted as untyped strings and a misspelling would have been just
   * as invisible. A CIBA client MUST tell "keep polling" apart from a real failure.
   */
  it('expresses the backchannel codes, which a polling client must act on', () => {
    for (const code of ['authorization_pending', 'slow_down', 'expired_token', 'unknown_user_id'] as const) {
      expect(oauthError(code).error).toBe(code);
    }
  });

  it('expresses the resource indicator refusal, so narrowing an audience can fail precisely', () => {
    // RFC 8707 2.2. Needed by P3, and in the set from the start so P3 adds no code of its own.
    expect(oauthError('invalid_target').error).toBe('invalid_target');
  });

  /**
   * Not a runtime assertion, and deliberately so: the guarantee is a compile-time one. An invented
   * code does not fail this test, it fails `tsc`, which is the earlier and louder of the two.
   */
  it('rejects an invented code at compile time rather than at runtime', () => {
    // @ts-expect-error a code outside the closed set must not type-check
    const invented: OAuthErrorCode = 'nearly_right';
    expect(typeof invented).toBe('string');
  });
});
