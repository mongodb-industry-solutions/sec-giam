// GIAM's binding for the shared eventbus package: its own settings, its own database, its own event
// store. The implementation is shared; the instances never see each other, which is what keeps the
// boundary between the identity authority and its consumers a network contract rather than a bus.
import {
  initEventBus as initSharedEventBus,
  resolveEventBusEngine as resolveSharedEngine,
  type EventBus,
  type EventBusEngine,
  type EventBusSettings,
  type EventStore,
  type EventStoreDb,
} from '@leafypay/eventbus';
import { config } from '../../config';

function giamSettings(): EventBusSettings {
  return {
    engine: config.app.eventBusEngine,
    topicPrefix: config.app.eventBusTopicPrefix,
    kafka: {
      brokers: config.kafka.brokers,
      clientId: config.kafka.clientId,
      ssl: config.kafka.ssl,
      saslMechanism: config.kafka.saslMechanism,
      saslUsername: config.kafka.saslUsername,
      saslPassword: config.kafka.saslPassword,
    },
    rabbitmq: { url: config.rabbitmq.url },
  };
}

export function initEventBus(db: EventStoreDb, store?: EventStore): EventBus {
  return initSharedEventBus(db, giamSettings(), store);
}

export function resolveEventBusEngine(): EventBusEngine {
  return resolveSharedEngine(config.app.eventBusEngine);
}

export * from '@leafypay/eventbus';
