import { EventEmitter } from 'events';
import { EventBus, EventHandler, Subscription } from './EventBus';
import { EventStore } from './EventStore';
import { DomainEvent } from './types';
import { sanitizeDeep } from './sanitize';

const SEP = ' '; // composite-key separator; never present in an eventType

function toRegex(pattern: string): RegExp {
  return new RegExp('^' + pattern.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
}

interface Wildcard { regex: RegExp; correlationId?: string; handler: EventHandler; }

// In-process adapter. Exact event types dispatch via EventEmitter (name-indexed); a correlation-scoped
// sub uses an `eventType<sep>correlationId` key so a journey's subscribers fire in isolation; the few
// wildcard patterns are matched on publish. A broker adapter implements the same port.
// No store => transient bus (delivery only, e.g. ephemeral SSE signals).
export class EventBusInProcess implements EventBus {
  private readonly emitter = new EventEmitter();
  private readonly wildcards = new Set<Wildcard>();

  constructor(private readonly store?: EventStore) {
    this.emitter.setMaxListeners(0);
  }

  async start(): Promise<void> {}
  async stop(): Promise<void> { this.emitter.removeAllListeners(); this.wildcards.clear(); }

  async publish<T>(event: DomainEvent<T>): Promise<void> {
    const safe: DomainEvent = { ...event, payload: sanitizeDeep(event.payload) as Record<string, unknown> };
    if (this.store && !safe.transient) await this.store.append(safe); // transient = SSE signal, not persisted
    this.emitter.emit(safe.eventType, safe);
    this.emitter.emit(safe.eventType + SEP + safe.correlationId, safe);
    for (const w of this.wildcards) {
      if (w.regex.test(safe.eventType) && (!w.correlationId || w.correlationId === safe.correlationId)) this.deliver(w.handler, safe);
    }
  }

  subscribe(pattern: string | string[], handler: EventHandler, opts?: { group?: string; correlationId?: string }): Subscription {
    const offs: Array<() => void> = [];
    const wrapped = (e: DomainEvent) => this.deliver(handler, e);
    for (const p of (Array.isArray(pattern) ? pattern : [pattern])) {
      if (p.includes('*')) {
        const w: Wildcard = { regex: toRegex(p), correlationId: opts?.correlationId, handler };
        this.wildcards.add(w);
        offs.push(() => this.wildcards.delete(w));
      } else {
        const key = opts?.correlationId ? p + SEP + opts.correlationId : p;
        this.emitter.on(key, wrapped);
        offs.push(() => this.emitter.off(key, wrapped));
      }
    }
    return { unsubscribe: () => offs.forEach(f => f()) };
  }

  // Async + isolated: a handler error never blocks the publisher or other handlers.
  private deliver(handler: EventHandler, e: DomainEvent): void {
    Promise.resolve().then(() => handler(e)).catch(() => {});
  }
}
