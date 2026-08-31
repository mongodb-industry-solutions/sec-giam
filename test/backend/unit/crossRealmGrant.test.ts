// Realm isolation is the property everything else rests on, and the rule that decides which
// assignments reach which realm is two lines long. Two lines are exactly what gets edited by
// somebody fixing something else, so they are pinned here rather than left to a reviewer.
import { describe, it, expect } from 'vitest';
import {
  assignmentAppliesIn, REALM_SCOPE_KIND,
} from '../../../backend/src/modules/authorization/models/authorization.model';

const HOME = 'realm-home';
const OTHER = 'realm-other';

describe('an assignment reaching across realms', () => {
  it('grants at home when it names no realm', () => {
    expect(assignmentAppliesIn({}, HOME, HOME)).toBe(true);
  });

  it('never grants elsewhere just because it is unscoped', () => {
    expect(assignmentAppliesIn({}, HOME, OTHER)).toBe(false);
  });

  it('grants in the realm it names', () => {
    const held = { scope: { kind: REALM_SCOPE_KIND, ref: OTHER } };
    expect(assignmentAppliesIn(held, HOME, OTHER)).toBe(true);
  });

  it('does not widen the home realm by naming another', () => {
    const held = { scope: { kind: REALM_SCOPE_KIND, ref: OTHER } };
    expect(assignmentAppliesIn(held, HOME, HOME)).toBe(false);
  });

  it('grants in no third realm', () => {
    const held = { scope: { kind: REALM_SCOPE_KIND, ref: OTHER } };
    expect(assignmentAppliesIn(held, HOME, 'realm-third')).toBe(false);
  });

  it('treats an application scope as home-only, since only this authority reads realm scopes', () => {
    const held = { scope: { kind: 'case', ref: 'case-2291' } };
    expect(assignmentAppliesIn(held, HOME, HOME)).toBe(true);
    expect(assignmentAppliesIn(held, HOME, OTHER)).toBe(false);
  });
});
