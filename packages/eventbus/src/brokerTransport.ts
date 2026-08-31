// Transport abstraction the broker EventBus adapters delegate IO to. Keeping it separate lets the
// adapter logic (envelope mapping, fan-out, dedup, ordering) be unit-tested with a fake transport,
// and keeps the broker client libraries optional: they are loaded only when their engine is selected.

export interface BrokerMessage {
  key: string;                       // partition / ordering key (the journey correlationId)
  value: Buffer;                     // the serialized event envelope
  headers: Record<string, string>;  // lightweight routing/observability headers
}

export interface BrokerTransport {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  produce(topic: string, msg: BrokerMessage): Promise<void>;
  /** Start one consumer for `group` on `topic`; invoke `handler` per delivered message. */
  consume(topic: string, group: string, handler: (m: BrokerMessage) => Promise<void>): Promise<void>;
}

// Hidden from static analysis so the optional client packages are not required to compile/run the
// default in-process engine. They are imported only when a broker engine is actually selected.
const dynamicImport = new Function('m', 'return import(m)') as (m: string) => Promise<Record<string, unknown>>;
async function loadOptionalModule(name: string): Promise<Record<string, unknown>> {
  try {
    return await dynamicImport(name);
  } catch {
    throw new Error(`The '${name}' package is required for this event bus engine. Install it with: npm i ${name}`);
  }
}

function toHeaderStrings(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
      out[k] = Buffer.isBuffer(v) ? v.toString() : String(v ?? '');
    }
  }
  return out;
}

export interface KafkaTransportConfig {
  brokers: string[];
  clientId?: string;
  ssl?: boolean;
  sasl?: { mechanism: string; username: string; password: string };
}

export class KafkaTransport implements BrokerTransport {
  // External client loaded dynamically (kafkajs); untyped here.
  private kafka: any;
  private producer: any;
  private consumer: any;

  constructor(private readonly cfg: KafkaTransportConfig) {}

  async connect(): Promise<void> {
    const mod = await loadOptionalModule('kafkajs');
    const Kafka = mod.Kafka as new (o: unknown) => unknown;
    this.kafka = new Kafka({ clientId: this.cfg.clientId ?? 'pci-psp', brokers: this.cfg.brokers, ssl: this.cfg.ssl, ...(this.cfg.sasl ? { sasl: this.cfg.sasl } : {}) });
    this.producer = this.kafka.producer({ idempotent: true });
    await this.producer.connect();
  }

  async produce(topic: string, msg: BrokerMessage): Promise<void> {
    await this.producer.send({ topic, messages: [{ key: msg.key, value: msg.value, headers: msg.headers }] });
  }

  async consume(topic: string, group: string, handler: (m: BrokerMessage) => Promise<void>): Promise<void> {
    this.consumer = this.kafka.consumer({ groupId: group });
    await this.consumer.connect();
    await this.consumer.subscribe({ topic, fromBeginning: false });
    await this.consumer.run({
      eachMessage: async ({ message }: { message: { key?: Buffer; value: Buffer; headers?: unknown } }) => {
        await handler({ key: message.key?.toString() ?? '', value: message.value, headers: toHeaderStrings(message.headers) });
      },
    });
  }

  async disconnect(): Promise<void> {
    await this.producer?.disconnect().catch(() => {});
    await this.consumer?.disconnect().catch(() => {});
  }
}

export interface RabbitTransportConfig {
  url: string;
  exchange: string;
}

export class RabbitTransport implements BrokerTransport {
  // External client loaded dynamically (amqplib); untyped here.
  private conn: any;
  private ch: any;

  constructor(private readonly cfg: RabbitTransportConfig) {}

  async connect(): Promise<void> {
    const mod = await loadOptionalModule('amqplib');
    const connect = (mod.connect ?? (mod.default as { connect?: unknown })?.connect) as (url: string) => Promise<unknown>;
    this.conn = await connect(this.cfg.url);
    this.ch = await this.conn.createChannel();
    await this.ch.assertExchange(this.cfg.exchange, 'topic', { durable: true });
  }

  async produce(_topic: string, msg: BrokerMessage): Promise<void> {
    this.ch.publish(this.cfg.exchange, msg.headers.eventType ?? 'event', msg.value, { headers: msg.headers, persistent: msg.headers.transient !== '1' });
  }

  async consume(_topic: string, group: string, handler: (m: BrokerMessage) => Promise<void>): Promise<void> {
    const q = await this.ch.assertQueue(`${this.cfg.exchange}.${group}`, { durable: true });
    await this.ch.bindQueue(q.queue, this.cfg.exchange, '#');
    await this.ch.consume(q.queue, (raw: unknown) => {
      const m = raw as { content: Buffer; fields: { routingKey: string }; properties: { headers?: unknown } } | null;
      if (!m) return;
      void handler({ key: m.fields.routingKey, value: m.content, headers: toHeaderStrings(m.properties.headers) });
      this.ch.ack(m);
    });
  }

  async disconnect(): Promise<void> {
    await this.ch?.close().catch(() => {});
    await this.conn?.close().catch(() => {});
  }
}
