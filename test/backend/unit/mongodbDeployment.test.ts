// What each MongoDB deployment can do, and what GIAM does about it.
//
// The point of the module under test is that no feature is gated by a hand-managed flag, so these
// cases are the specification: given a type and a version, exactly one capability set follows. The
// ones that matter most are the negative ones. A deployment that CANNOT do something and is allowed
// to claim it does is how this codebase previously failed setup with the principal collection left
// uncreated, and how a Community cluster could hold a collection nothing could ever read.
import { describe, it, expect } from 'vitest';
import {
  parseVersion, atLeast, parseDeploymentType, capabilitiesOf, classifyProbe, capabilityFindings,
  MongoDeployment, MongoDeploymentType,
} from '../../../backend/src/vendors/mongodb/deployment';

function deployment(
  type: MongoDeploymentType,
  version: string,
  replicaSet = true,
): MongoDeployment {
  return { type, version: parseVersion(version), source: 'declared', replicaSet };
}

describe('version parsing', () => {
  it('reads a three part version', () => {
    expect(parseVersion('8.2.4')).toMatchObject({ major: 8, minor: 2, patch: 4 });
  });

  it('ignores a build or pre-release suffix, which never decides a capability', () => {
    expect(parseVersion('9.0.0-rc0')).toMatchObject({ major: 9, minor: 0, patch: 0 });
    expect(parseVersion('8.2')).toMatchObject({ major: 8, minor: 2, patch: 0 });
  });

  it('compares on major and minor only', () => {
    expect(atLeast(parseVersion('9.0.0'), 9, 0)).toBe(true);
    expect(atLeast(parseVersion('8.2.4'), 9, 0)).toBe(false);
    expect(atLeast(parseVersion('10.0.0'), 9, 0)).toBe(true);
  });
});

describe('the declared deployment type', () => {
  it('accepts the three names and their long forms', () => {
    expect(parseDeploymentType('atlas')).toBe('atlas');
    expect(parseDeploymentType('EA')).toBe('ea');
    expect(parseDeploymentType('enterprise')).toBe('ea');
    expect(parseDeploymentType('community')).toBe('ce');
  });

  // A typo in one variable must not take an identity provider down. The probe corrects it anyway.
  it('falls back to the reference deployment rather than refusing to start', () => {
    expect(parseDeploymentType(undefined)).toBe('atlas');
    expect(parseDeploymentType('atlas-serverless')).toBe('atlas');
  });
});

describe('capabilities follow from the deployment', () => {
  it('gives Atlas 9.0 everything this codebase uses', () => {
    const caps = capabilitiesOf(deployment('atlas', '9.0.0'));
    expect(caps).toMatchObject({
      automaticEncryption: true,
      qeRange: true,
      changeStreams: true,
      timeSeriesExpiry: true,
      atlasSearch: true,
    });
    expect(caps.qeTextSearchProfile).toMatchObject({ textSearch: true, substring: 'substring' });
  });

  // 8.2-8.3 only knows the preview spellings; declaring the GA name there fails setup.
  it('uses the preview substring query type on 8.2, and none below it', () => {
    const caps = capabilitiesOf(deployment('ea', '8.2.4'));
    expect(caps.automaticEncryption).toBe(true);
    expect(caps.qeTextSearchProfile).toMatchObject({ textSearch: true, substring: 'substringPreview' });
    expect(caps.qeRange).toBe(true);
    expect(capabilitiesOf(deployment('ea', '8.0.0')).qeTextSearchProfile.textSearch).toBe(false);
  });

  it('withholds automatic encryption from Community at every version', () => {
    for (const version of ['7.0.0', '8.2.4', '9.0.0']) {
      const caps = capabilitiesOf(deployment('ce', version));
      expect(caps.automaticEncryption, version).toBe(false);
      // And with it, every encrypted query type: an index nothing can analyse buys nothing.
      expect(caps.qeTextSearchProfile.textSearch, version).toBe(false);
      expect(caps.qeRange, version).toBe(false);
    }
  });

  it('withholds Queryable Encryption entirely below 7.0', () => {
    expect(capabilitiesOf(deployment('atlas', '6.0.0')).queryableEncryption).toBe(false);
  });

  it('ties change streams and transactions to the topology, not to the edition', () => {
    expect(capabilitiesOf(deployment('ea', '8.2.4', false)).changeStreams).toBe(false);
    expect(capabilitiesOf(deployment('ea', '8.2.4', true)).changeStreams).toBe(true);
  });

  it('reserves Atlas Search for Atlas', () => {
    expect(capabilitiesOf(deployment('ea', '9.0.0')).atlasSearch).toBe(false);
    expect(capabilitiesOf(deployment('atlas', '8.2.4')).atlasSearch).toBe(true);
  });
});

describe('probing a live cluster', () => {
  it('recognises Atlas from the server, and from the host as a fallback', () => {
    expect(classifyProbe({ version: '8.2.4', atlasVersion: '1.0' }, { setName: 'rs0' }, 'mongodb://x')
      .type).toBe('atlas');
    expect(classifyProbe({ version: '8.2.4' }, { setName: 'rs0' }, 'mongodb+srv://c0.ab12.mongodb.net')
      .type).toBe('atlas');
  });

  it('separates Enterprise from Community by the loaded modules', () => {
    expect(classifyProbe({ version: '8.2.4', modules: ['enterprise'] }, {}, 'mongodb://h').type).toBe('ea');
    expect(classifyProbe({ version: '8.2.4', modules: [] }, {}, 'mongodb://h').type).toBe('ce');
  });

  it('counts a mongos as capable of change streams, like a replica set', () => {
    expect(classifyProbe({ version: '8.2.4' }, { msg: 'isdbgrid' }, 'mongodb://h').replicaSet).toBe(true);
    expect(classifyProbe({ version: '8.2.4' }, {}, 'mongodb://h').replicaSet).toBe(false);
  });
});

describe('what an operator is told', () => {
  it('warns when the deployment cannot encrypt at all', () => {
    const findings = capabilityFindings(deployment('ce', '8.2.4'));
    expect(findings.some((f) => f.warn && /Community/.test(f.text))).toBe(true);
  });

  // Degradation is reported without being alarming: the data is still encrypted and still exactly
  // searchable, so this is a lost query shape and not a lost control.
  it('reports the substring fallback as information, not as a warning', () => {
    const finding = capabilityFindings(deployment('atlas', '8.0.0'))
      .find((f) => /substring/.test(f.text));
    expect(finding?.warn).toBe(false);
  });

  it('surfaces a declaration that disagrees with the cluster', () => {
    const mismatched = { ...deployment('atlas', '9.0.0'), mismatch: 'declares "atlas" but the cluster is "ea"' };
    expect(capabilityFindings(mismatched).some((f) => f.warn && /declares/.test(f.text))).toBe(true);
  });
});
