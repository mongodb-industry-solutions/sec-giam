import { EventBus, EventHandler, Subscription } from './EventBus';
import { EventStore } from './EventStore';
import { DomainEvent } from './types';
import { sanitizeDeep } from './sanitize';
import { BrokerTransport } from './brokerTransport';

// Broker-backed EventBus. Publishers produce one serialized envelope per event to a single event-log
// topic, keyed by partitionKey (= correlationId) so a journey stays ordered on one partition. A single
// internal consumer reads the topic and fans out to the in-process subscriptions, matching the same
// pattern/correlationId semantics as the in-process adapter. The domain-event store is written here on
// delivery (idempotent by eventId), so the correlated trail exists under any engine. Kafka and Rabbit
// differ only in the injected transport.

const INTERNAL_GROUP = 'eventbus-core';
const SEEN_CAP = 50_000; // bound the in-memory dedup set

function toRegex(pattern: string): RegExp {
  return new RegExp('^' + pattern.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
}

interface Sub { regex: RegExp; correlationId?: string; handler: EventHandler; }

export class BrokerEventBus implements EventBus {
  private readonly subs = new Set<Sub>();
  private readonly seen = new Set<string>();
  private started = false;

  constructor(private readonly transport: BrokerTransport, private readonly opts: { topic: string; store?: EventStore }) {}

  async start(): Promise<void> {
    if (this.started) return;
    await this.transport.connect();
    await this.transport.consume(this.opts.topic, INTERNAL_GROUP, (m) => this.onMessage(m.value));
    this.started = true;
  }

  async stop(): Promise<void> {
    await this.transport.disconnect();
    this.subs.clear();
    this.seen.clear();
    this.started = false;
  }

  async publish<T>(event: DomainEvent<T>): Promise<void> {
    const safe: DomainEvent = { ...event, payload: sanitizeDeep(event.payload) as Record<string, unknown> };
    await this.transport.produce(this.opts.topic, {
      key: safe.partitionKey ?? safe.correlationId,
      value: Buffer.from(JSON.stringify(safe)),
      headers: {
        eventType: safe.eventType,
        correlationId: safe.correlationId,
        eventId: safe.eventId,
        transient: safe.transient ? '1' : '0',
      },
    });
  }

  subscribe(pattern: string | string[], handler: EventHandler, opts?: { group?: string; correlationId?: string }): Subscription {
    const local: Sub[] = [];
    for (const p of Array.isArray(pattern) ? pattern : [pattern]) {
      const s: Sub = { regex: toRegex(p), correlationId: opts?.correlationId, handler };
      this.subs.add(s);
      local.push(s);
    }
    return { unsubscribe: () => local.forEach((s) => this.subs.delete(s)) };
  }

  private async onMessage(value: Buffer): Promise<void> {
    let event: DomainEvent;
    try { event = JSON.parse(value.toString()) as DomainEvent; } catch { return; }
    if (this.seen.has(event.eventId)) return; // at-least-once delivery → dedup by eventId
    if (this.seen.size >= SEEN_CAP) this.seen.clear();
    this.seen.add(event.eventId);
    if (this.opts.store && !event.transient) { try { await this.opts.store.append(event); } catch { /* idempotent append */ } }
    for (const s of this.subs) {
      if (s.regex.test(event.eventType) && (!s.correlationId || s.correlationId === event.correlationId)) this.deliver(s.handler, event);
    }
  }

  // Async + isolated: a handler error never blocks delivery to the others.
  private deliver(handler: EventHandler, e: DomainEvent): void {
    Promise.resolve().then(() => handler(e)).catch(() => {});
  }
}
