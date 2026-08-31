import { BrokerEventBus } from './BrokerEventBus';
import { RabbitTransport, RabbitTransportConfig } from './brokerTransport';
import { EventStore } from './EventStore';

// RabbitMQ-backed EventBus: the same port, backed by a topic-exchange transport. Selected via
// PSP_EVENT_BUS_ENGINE.
export class EventBusRabbit extends BrokerEventBus {
  constructor(cfg: RabbitTransportConfig & { topic: string }, store?: EventStore) {
    super(new RabbitTransport(cfg), { topic: cfg.topic, store });
  }
}
