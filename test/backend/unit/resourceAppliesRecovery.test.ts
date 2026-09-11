// A `resource.pattern` that does not compile under RE2 must not crash whatever reads it. This can
// only happen for a document written before `validatePolicy` started refusing one (or written some
// other way), but "should not happen" is exactly the case worth a test: the failure mode observed
// was a live resource detail page returning a 500 because one policy's pattern would not compile.
import { describe, it, expect } from 'vitest';
import { selectorApplies } from '../../../backend/src/modules/authorization/models/policy.model';

describe('selectorApplies survives a pattern that will not compile', () => {
  it('treats an uncompilable pattern as matching nothing, rather than throwing', () => {
    // A lone `*` was the old glob sentinel for "matches everything"; as a real regular expression
    // it is "nothing to repeat", which RE2 refuses to compile.
    expect(() => selectorApplies({ pattern: '*' }, 'reports')).not.toThrow();
    expect(selectorApplies({ pattern: '*' }, 'reports')).toBe(false);
  });

  it('still matches normally for every other policy once one has a broken pattern', () => {
    expect(selectorApplies({ pattern: '*' }, 'reports')).toBe(false);
    // The cache keyed by the broken pattern string must not affect an unrelated, valid one.
    expect(selectorApplies({ pattern: '^reports' }, 'reports')).toBe(true);
    expect(selectorApplies({ ids: ['reports'] }, 'reports')).toBe(true);
  });

  it('caches the failure rather than re-throwing on a second read of the same pattern', () => {
    for (let i = 0; i < 3; i += 1) {
      expect(() => selectorApplies({ pattern: '*' }, 'sessions')).not.toThrow();
    }
  });
});
