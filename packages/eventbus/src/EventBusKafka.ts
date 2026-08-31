import { BrokerEventBus } from './BrokerEventBus';
import { KafkaTransport, KafkaTransportConfig } from './brokerTransport';
import { EventStore } from './EventStore';

// Kafka-backed EventBus: the same port, backed by a Kafka transport. Selected via PSP_EVENT_BUS_ENGINE.
export class EventBusKafka extends BrokerEventBus {
  constructor(cfg: KafkaTransportConfig & { topic: string }, store?: EventStore) {
    super(new KafkaTransport(cfg), { topic: cfg.topic, store });
  }
}
