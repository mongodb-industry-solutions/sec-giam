// EventBus package entry point. App calls initEventBus at startup; everything else uses getEventBus().
// v37: shared by the PSP and bankcore, so settings arrive as an argument instead of an app config.
import { EventBus } from './EventBus';
import { EventBusInProcess } from './EventBusInProcess';
import { EventBusKafka } from './EventBusKafka';
import { EventBusRabbit } from './EventBusRabbit';
import { MongoEventStore, EventStore, EventStoreDb } from './EventStore';
import { v4 as uuidv4 } from 'uuid';
import { DomainEvent, BusinessProcess } from './types';

let instance: EventBus | null = null;

// Settings the host application supplies; all optional, the default engine is in-process.
export interface EventBusSettings {
  engine?: string;
  topicPrefix?: string;
  kafka?: {
    brokers: string[];
    clientId: string;
    ssl: boolean;
    saslMechanism?: string;
    saslUsername?: string;
    saslPassword?: string;
  };
  rabbitmq?: { url: string };
}

const DEFAULT_TOPIC_PREFIX = 'pci.psp';

// The bus engine is chosen by configuration (Strategy pattern): switching engines needs no
// publisher/consumer code change, only this selection. Every engine implements the same EventBus port.
export type EventBusEngine = 'in-process' | 'kafka' | 'rabbitmq';

const SUPPORTED_ENGINES = ['in-process', 'kafka', 'rabbitmq'] as const;

// Returns the value only if it is a supported engine; otherwise null (blank/unknown → null).
function coerceEngine(value: string | undefined | null): EventBusEngine | null {
  const v = value?.trim();
  return v && (SUPPORTED_ENGINES as readonly string[]).includes(v) ? (v as EventBusEngine) : null;
}

export function resolveEventBusEngine(configuredEngine?: string): EventBusEngine {
  // Read live from the environment (PSP_-prefixed, then legacy) so the engine can be selected at
  // startup regardless of when the config snapshot was taken. Validate against SUPPORTED_ENGINES:
  // an unsupported or blank value must NOT silently resolve to in-process (that masks a production
  // misconfiguration): warn, then fall back to the validated config default (ultimately in-process).
  const fromEnv = process.env.PSP_EVENT_BUS_ENGINE ?? process.env.EVENT_BUS_ENGINE;
  const envEngine = coerceEngine(fromEnv);
  if (envEngine) return envEngine;
  const fallback = coerceEngine(configuredEngine) ?? 'in-process';
  if (fromEnv?.trim()) {
    console.warn(
      `[eventbus] Ignoring unsupported EVENT_BUS_ENGINE="${fromEnv}". ` +
      `Supported: ${SUPPORTED_ENGINES.join(', ')}. Falling back to "${configuredEngine}".`,
    );
  }
  return fallback;
}

export function initEventBus(db: EventStoreDb, settings?: EventBusSettings, store?: EventStore): EventBus {
  const engine = resolveEventBusEngine(settings?.engine);
  const eventStore = store ?? new MongoEventStore(db);
  const topic = `${settings?.topicPrefix ?? DEFAULT_TOPIC_PREFIX}.domain-events`;

  // A broker engine without its settings is a misconfiguration; falling back to in-process hides it.
  if (engine === 'kafka') {
    const k = settings?.kafka;
    if (!k) throw new Error('EventBus engine "kafka" selected but no kafka settings were supplied');
    instance = new EventBusKafka({ brokers: k.brokers, clientId: k.clientId, ssl: k.ssl, sasl: buildKafkaSasl(k), topic }, eventStore);
    return instance;
  }
  if (engine === 'rabbitmq') {
    if (!settings?.rabbitmq) throw new Error('EventBus engine "rabbitmq" selected but no rabbitmq settings were supplied');
    instance = new EventBusRabbit({ url: settings.rabbitmq.url, exchange: topic, topic }, eventStore);
    return instance;
  }
  instance = new EventBusInProcess(eventStore);
  return instance;
}

function buildKafkaSasl(
  k: NonNullable<EventBusSettings['kafka']>,
): { mechanism: string; username: string; password: string } | undefined {
  return k.saslMechanism && k.saslUsername && k.saslPassword
    ? { mechanism: k.saslMechanism, username: k.saslUsername, password: k.saslPassword }
    : undefined;
}

export function getEventBus(): EventBus {
  if (!instance) throw new Error('EventBus not initialized; call initEventBus(db) at startup');
  return instance;
}

export function setEventBus(bus: EventBus): void { instance = bus; }

// Builds a DomainEvent with defaults (eventId/occurredAt auto-filled; partitionKey = correlationId).
export function makeEvent<T>(input: {
  eventType: string;
  correlationId: string;
  businessProcess: BusinessProcess;
  payload: T;
  causationId?: string;
  source?: string;
  partitionKey?: string;
  actor?: DomainEvent['actor'];
  bian?: DomainEvent['bian'];
  transient?: boolean;
}): DomainEvent<T> {
  return {
    eventId: uuidv4(),
    eventType: input.eventType,
    occurredAt: new Date().toISOString(),
    correlationId: input.correlationId,
    causationId: input.causationId,
    businessProcess: input.businessProcess,
    partitionKey: input.partitionKey ?? input.correlationId,
    source: input.source ?? 'psp.core',
    actor: input.actor,
    bian: input.bian,
    payload: input.payload,
    schemaVersion: 1,
    ...(input.transient ? { transient: true } : {}),
  };
}

export * from './types';
export * from './EventBus';
export * from './signals';
export { MongoEventStore, DOMAIN_EVENT_COLLECTION } from './EventStore';
export type { EventStore, EventStoreDb, EventStoreCollection, EventStoreCursor } from './EventStore';
// Engines and transports are part of the surface, so consumers need one import path.
export { EventBusInProcess } from './EventBusInProcess';
export { EventBusKafka } from './EventBusKafka';
export { EventBusRabbit } from './EventBusRabbit';
export { BrokerEventBus } from './BrokerEventBus';
export * from './sanitize';
export { KafkaTransport, RabbitTransport } from './brokerTransport';
export type { BrokerTransport, KafkaTransportConfig, RabbitTransportConfig } from './brokerTransport';
