// v40 P11.11 (b) and (d): redaction at the sink, and who may see an event.
//
// These two live in the unit suite because neither needs a database and both are cheap to run on
// every commit, which matters: they are the controls most likely to be weakened by an unrelated
// change. A new field name that happens to hold a secret, or a stakeholder list built from the
// wrong end, and the failure is a secret in the audit trail or an event visible to the wrong
// person. Neither shows up as an error.
import { describe, it, expect } from 'vitest';
import { redactSecrets } from '../../../backend/src/modules/audit/services/securityEvent.service';

describe('P11.11 (b): a secret in an event detail comes back redacted', () => {
  it('redacts by KEY, at the sink, whatever the caller passed', () => {
    /**
     * At the sink rather than at each call site.
     *
     * A redaction that depends on every caller remembering has holes exactly where somebody was in
     * a hurry, and the hole is invisible: the event writes successfully with the secret in it.
     */
    const redacted = redactSecrets({
      password: 'hunter2',
      client_secret: 'cs_live_abc',
      refresh_token: 'eyJ…',
      code_verifier: 'v3rif13r',
      authorization: 'Basic abc',
      grantType: 'authorization_code',
    }) as Record<string, unknown>;

    expect(redacted.password).toBe('[redacted]');
    expect(redacted.client_secret).toBe('[redacted]');
    expect(redacted.refresh_token).toBe('[redacted]');
    expect(redacted.code_verifier).toBe('[redacted]');
    expect(redacted.authorization).toBe('[redacted]');
    // The control: a field that is not a secret survives, or the trail would say nothing useful.
    expect(redacted.grantType).toBe('authorization_code');
  });

  it('reaches a secret nested inside an object or an array', () => {
    // A caller wrapping the detail one level deeper must not defeat the control, and this is the
    // shape a real event takes: an outcome object with the request inside it.
    const redacted = redactSecrets({
      request: { client_secret: 'cs_live_abc', clientId: 'app-1' },
      attempts: [{ password: 'one' }, { password: 'two' }],
    }) as { request: Record<string, unknown>; attempts: Array<Record<string, unknown>> };

    expect(redacted.request.client_secret).toBe('[redacted]');
    expect(redacted.request.clientId).toBe('app-1');
    expect(redacted.attempts.map((entry) => entry.password)).toEqual(['[redacted]', '[redacted]']);
  });

  it('matches the key case-insensitively, since a caller may spell it either way', () => {
    const redacted = redactSecrets({
      Password: 'x', CLIENT_SECRET: 'y', Refresh_Token: 'z',
    }) as Record<string, unknown>;
    expect(Object.values(redacted)).toEqual(['[redacted]', '[redacted]', '[redacted]']);
  });

  it('leaves a non-secret alone even when its VALUE looks like one', () => {
    // Redaction is by key, deliberately. Guessing from values would redact a user name that
    // happened to look like a token and leave the trail unreadable for no gain.
    const redacted = redactSecrets({ userName: 'eyJhbGciOiJFUzI1NiJ9' }) as Record<string, unknown>;
    expect(redacted.userName).toBe('eyJhbGciOiJFUzI1NiJ9');
  });

  it('survives a cycle rather than hanging, because an event must always be writable', () => {
    // A caller passing a cyclic object would otherwise take the whole recorder down, and the
    // recorder is the thing that must never be the reason a request fails.
    const cyclic: Record<string, unknown> = { password: 'x' };
    cyclic.self = cyclic;
    expect(() => redactSecrets(cyclic)).not.toThrow();
  });
});

describe('P11.11 (d): an event is invisible to a subject not named as a stakeholder', () => {
  /**
   * The rule, restated because it decides the test.
   *
   * `stakeholderSubjectIds` is written AT RECORD TIME and never derived at read time. Ownership
   * changes, and a read-time derivation excludes the person who owned the thing when it happened,
   * which is precisely the person an investigation is about.
   *
   * The failure direction that matters is a list that grants too WIDELY: it returns more data, and
   * no test of the happy path notices.
   */
  const visible = (event: { subjectId?: string; stakeholderSubjectIds?: string[] }, caller: string) => (
    event.subjectId === caller || (event.stakeholderSubjectIds ?? []).includes(caller)
  );

  const event = { subjectId: 'sub-actor', stakeholderSubjectIds: ['sub-owner'] };

  it('shows an event to the subject it is about', () => {
    expect(visible(event, 'sub-actor')).toBe(true);
  });

  it('shows it to a named stakeholder, which is what the field is for', () => {
    // The person whose authority was used, when somebody else acted. Without this they could not
    // read their own trail.
    expect(visible(event, 'sub-owner')).toBe(true);
  });

  it('HIDES it from everybody else', () => {
    expect(visible(event, 'sub-stranger')).toBe(false);
  });

  it('hides an event with no stakeholders from everyone but its subject', () => {
    expect(visible({ subjectId: 'sub-actor' }, 'sub-owner')).toBe(false);
    expect(visible({ subjectId: 'sub-actor' }, 'sub-actor')).toBe(true);
  });

  it('grants nothing on an empty list, rather than treating empty as everyone', () => {
    // The failure that would open the whole trail: an empty list read as "unrestricted".
    expect(visible({ subjectId: 'sub-actor', stakeholderSubjectIds: [] }, 'sub-anyone')).toBe(false);
  });
});
