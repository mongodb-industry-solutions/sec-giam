// v40 P10: a revocation has to reach a resource server that verifies tokens on its own.
//
// The gap this closes is the one local verification creates. Deleting a session ends access here
// immediately, and a resource server checking a signature against the published key set carries on
// honouring the holder's existing token until it expires. Three layers answer that, and this suite
// tests the two that are code rather than configuration.
//
// The receiver is a REAL HTTP server, in process. A stubbed `fetch` would assert that we call a
// function, which is not the claim: the claim is that a subscribed receiver receives a verifiable
// Security Event Token over the wire.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, Server } from 'http';
import type { AddressInfo } from 'net';
import type { Db } from 'mongodb';
import { SignalsService } from '../../../backend/src/modules/authorization/services/signals.service';
import type { ResourceRecord } from '../../../backend/src/modules/authorization/models/resource.model';
import type { KeyRing } from '../../../backend/src/modules/keys/services/keyRing.service';

/** A receiver that records what it was sent, and can be told to fail. */
function receiver() {
  const received: string[] = [];
  let status = 202;

  const server: Server = createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      if (status < 400) received.push(body);
      response.writeHead(status).end();
    });
  });

  return {
    received,
    fail(code: number) { status = code; },
    listen: () => new Promise<number>((resolve) => {
      server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
    }),
    close: () => new Promise<void>((resolve) => { server.close(() => resolve()); }),
    contentTypes: [] as string[],
  };
}

/** A signing ring that produces a deterministic, inspectable signature. */
const ring = {
  signingKid: async () => 'kid-1',
  sign: async () => ({ kid: 'kid-1', signature: Buffer.from('signature') }),
} as unknown as KeyRing;

function resourcesHolding(resources: ResourceRecord[]): Db {
  return {
    collection() {
      return {
        find(filter: Record<string, unknown>) {
          const wanted = (filter['signalStream.events'] as string) ?? null;
          return {
            toArray: async () => resources.filter((resource) => (
              resource.status === 'active'
              && (!wanted || (resource.signalStream?.events ?? []).includes(wanted))
            )),
          };
        },
      };
    },
  } as unknown as Db;
}

const PUSH_RECEIVER: ResourceRecord = {
  realmId: 'r1',
  tenantId: 'default',
  resourceId: 'resource:api:payments',
  kind: 'api',
  name: 'payments',
  audience: 'https://api.example/payments',
  actions: ['read', 'refund'],
  catalogVersion: 1,
  status: 'active',
  signalStream: { deliveryMethod: 'push', endpoint: '', events: ['session-revoked'] },
  meta: { resourceType: 'Resource', created: 'x', lastModified: 'x', version: 'W/"1"' },
};

describe('P10.1: stream configuration is a sub document, not a collection', () => {
  it('carries the receiver configuration on the resource itself', () => {
    // Bounded, read with the resource, and replaced as a block. A collection for this would have
    // made the model fourteen to hold three fields nobody queries independently.
    expect(PUSH_RECEIVER.signalStream?.deliveryMethod).toBe('push');
    expect(PUSH_RECEIVER.signalStream?.events).toContain('session-revoked');
  });

  it('finds only the resources subscribed to the event being emitted', async () => {
    const other: ResourceRecord = {
      ...PUSH_RECEIVER,
      resourceId: 'resource:api:accounts',
      signalStream: { deliveryMethod: 'push', endpoint: '', events: ['credential-change'] },
    };
    const signals = new SignalsService(resourcesHolding([PUSH_RECEIVER, other]), ring);
    const subscribed = await signals.subscribers('r1', 'session-revoked');
    expect(subscribed.map((entry) => entry.resourceId)).toEqual(['resource:api:payments']);
  });

  it('does not consider a withdrawn resource subscribed', async () => {
    const withdrawn: ResourceRecord = { ...PUSH_RECEIVER, status: 'withdrawn' };
    const signals = new SignalsService(resourcesHolding([withdrawn]), ring);
    expect(await signals.subscribers('r1', 'session-revoked')).toEqual([]);
  });
});

describe('P10.2: the signal is a signed CAEP event a receiver can verify', () => {
  it('names the CAEP event type by its URI, not by our own word for it', async () => {
    // A receiver matches on the standard URI. Emitting our own vocabulary would mean every consumer
    // needs a mapping table that only we know about.
    const signals = new SignalsService(resourcesHolding([]), ring);
    const minted = await signals.mint({
      realmId: 'r1',
      tenantId: 'default',
      event: 'session-revoked',
      subjectId: 'sub-1',
      sessionId: 'sess-1',
      reason: 'logout',
    }, 'https://authority.example/realms/leafypay');

    const payload = JSON.parse(Buffer.from(minted.jwt.split('.')[1], 'base64url').toString('utf8'));
    expect(Object.keys(payload.events)).toEqual([
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
    ]);
    const event = payload.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked'];
    expect(event.subject).toEqual({ format: 'opaque', id: 'sub-1' });
    expect(event.session).toEqual({ format: 'opaque', id: 'sess-1' });
    expect(payload.iss).toBe('https://authority.example/realms/leafypay');
    expect(payload.jti).toBeTruthy();
  });

  it('is signed, because an unsigned one is a forgeable instruction to end a session', async () => {
    const signals = new SignalsService(resourcesHolding([]), ring);
    const minted = await signals.mint({
      realmId: 'r1', tenantId: 'default', event: 'session-revoked', subjectId: 'sub-1',
    }, 'https://authority.example/realms/leafypay');
    const [header, payload, signature] = minted.jwt.split('.');
    expect(header && payload && signature).toBeTruthy();
    expect(signature.length).toBeGreaterThan(0);
    // A dedicated media type, so a receiver can tell a signal from an access token.
    const decoded = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    expect(decoded.typ).toBe('secevent+jwt');
  });
});

describe('P10: a revocation reaches a subscribed receiver, over the wire', () => {
  const target = receiver();
  let port = 0;

  beforeAll(async () => { port = await target.listen(); });
  afterAll(async () => { await target.close(); });

  it('delivers the token to the configured endpoint', async () => {
    const subscribed: ResourceRecord = {
      ...PUSH_RECEIVER,
      signalStream: { deliveryMethod: 'push', endpoint: `http://127.0.0.1:${port}/ssf`, events: ['session-revoked'] },
    };
    const signals = new SignalsService(resourcesHolding([subscribed]), ring);
    const minted = await signals.mint({
      realmId: 'r1', tenantId: 'default', event: 'session-revoked', subjectId: 'sub-1', sessionId: 'sess-1',
    }, 'https://authority.example/realms/leafypay');

    const outcomes = await signals.deliver(minted, [subscribed]);
    expect(outcomes).toEqual([{ resourceId: 'resource:api:payments', delivered: true, status: 202 }]);
    // The receiver got the SAME token, not a re-serialisation of it.
    expect(target.received).toContain(minted.jwt);
  });

  it('reports a refusing receiver rather than throwing', async () => {
    // A revocation that could be blocked by an unreachable third party would be one an attacker
    // could prevent by making that party unreachable.
    target.fail(500);
    const subscribed: ResourceRecord = {
      ...PUSH_RECEIVER,
      signalStream: { deliveryMethod: 'push', endpoint: `http://127.0.0.1:${port}/ssf`, events: ['session-revoked'] },
    };
    const signals = new SignalsService(resourcesHolding([subscribed]), ring);
    const minted = await signals.mint({
      realmId: 'r1', tenantId: 'default', event: 'session-revoked', subjectId: 'sub-1',
    }, 'https://authority.example/realms/leafypay');
    const outcomes = await signals.deliver(minted, [subscribed]);
    expect(outcomes[0].delivered).toBe(false);
    expect(outcomes[0].status).toBe(500);
    target.fail(202);
  });

  it('reports an unreachable receiver rather than throwing', async () => {
    const unreachable: ResourceRecord = {
      ...PUSH_RECEIVER,
      // A port nothing is listening on. Refused immediately rather than after the timeout.
      signalStream: { deliveryMethod: 'push', endpoint: 'http://127.0.0.1:1/ssf', events: ['session-revoked'] },
    };
    const signals = new SignalsService(resourcesHolding([unreachable]), ring);
    const minted = await signals.mint({
      realmId: 'r1', tenantId: 'default', event: 'session-revoked', subjectId: 'sub-1',
    }, 'https://authority.example/realms/leafypay');
    const outcomes = await signals.deliver(minted, [unreachable]);
    expect(outcomes[0].delivered).toBe(false);
    expect(outcomes[0].error).toBeTruthy();
  });

  it('does not post to a receiver that asked to POLL instead', async () => {
    // Delivering to a poll receiver would be interrupting somebody who explicitly asked not to be.
    const polling: ResourceRecord = {
      ...PUSH_RECEIVER,
      signalStream: { deliveryMethod: 'poll', events: ['session-revoked'] },
    };
    const signals = new SignalsService(resourcesHolding([polling]), ring);
    const minted = await signals.mint({
      realmId: 'r1', tenantId: 'default', event: 'session-revoked', subjectId: 'sub-1',
    }, 'https://authority.example/realms/leafypay');
    expect(await signals.deliver(minted, [polling])).toEqual([]);
  });
});
