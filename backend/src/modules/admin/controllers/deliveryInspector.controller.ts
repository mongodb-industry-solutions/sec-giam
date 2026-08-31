import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { ServerResponse } from 'http';
import { v4 as uuidv4 } from 'uuid';
import { problem } from '../../../shared/models/problem';
import { appendLog } from '../../../shared/services/logBuffer';
import { beginSSE, SSE_HEARTBEAT_FRAME, SSE_HEARTBEAT_MS } from '../../../shared/services/sse';
import { requireAdmin } from '../../../vendors/middleware/adminAuth';

/**
 * A receiver an operator can point an outbound delivery target at, to see what it actually sends.
 *
 * GIAM delivers lifecycle events to endpoints it does not own, so when a downstream system says it
 * received nothing there is no shared artefact to look at: one side has a log the other cannot read.
 * This endpoint accepts a delivery, records exactly what arrived, and shows it. It exists to end that
 * argument, and it is why the receiver is public: an emitter under test cannot be asked to hold an
 * operator credential. What is public is only the RECEIVING; reading what was received is not.
 *
 * In memory and capped, on purpose. This is a mirror held up to traffic, not a record of it, and an
 * inspector that persisted deliveries would quietly become a second copy of data that already has an
 * owner.
 */

interface DeliveryEntry {
  id: string;
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: unknown;
  timestamp: string;
  ip: string;
  response: { status: number; body: unknown };
}

const MAX_ENTRIES = 200;
const entries: DeliveryEntry[] = [];
const watchers = new Set<ServerResponse>();

// An authorization header on a captured delivery is a live credential. It is what an operator most
// wants to check and the last thing that should sit in a browser's storage in full.
const CREDENTIAL_HEADERS = ['authorization', 'proxy-authorization', 'cookie', 'set-cookie', 'dpop'];

function redactHeaders(headers: Record<string, unknown>): Record<string, string> {
  const safe: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    const text = Array.isArray(value) ? value.join(', ') : String(value ?? '');
    safe[name] = CREDENTIAL_HEADERS.includes(name.toLowerCase())
      ? `${text.slice(0, 12)}... (${text.length} chars, withheld)`
      : text;
  }
  return safe;
}

function broadcast(event: string, text: string): void {
  const frame = `event: ${event}\ndata: ${JSON.stringify({ text })}\n\n`;
  for (const watcher of [...watchers]) {
    try { watcher.write(frame); } catch { watchers.delete(watcher); }
  }
}

const NO_STANDARD = 'No applicable standard.';

/**
 * The receiver is open, so the only thing standing between it and a flood is this.
 *
 * What it protects is real but narrow: the capture list is capped and first in, first out, so an
 * anonymous caller who could post without limit would push every genuine capture out of the window an
 * operator is trying to read. Sixty a minute per address is well above what an emitter under test
 * produces and well below what erases anything.
 */
const RECEIVER_LIMIT_PER_MINUTE = 60;
const receiverSeen = new Map<string, { count: number; reset: number }>();

function receiverAllows(ip: string): boolean {
  const now = Date.now();
  const entry = receiverSeen.get(ip);
  if (!entry || entry.reset < now) {
    receiverSeen.set(ip, { count: 1, reset: now + 60_000 });
    return true;
  }
  if (entry.count >= RECEIVER_LIMIT_PER_MINUTE) return false;
  entry.count += 1;
  return true;
}

const receiverSchema = (method: string) => ({
  operationId: `receiveDelivery${method.charAt(0) + method.slice(1).toLowerCase()}`,
  tags: ['admin'],
  summary: `Receive a ${method} delivery for inspection`,
  description:
    `${NO_STANDARD} Accepts a delivery of any shape and records what arrived, so an operator can `
    + 'point an outbound target here and see exactly what this service sends. It is a mirror and '
    + 'nothing else: it changes no record, starts no flow and reaches no other part of the service, '
    + 'so an anonymous caller drives nothing by reaching it. It is open because an emitter under test '
    + 'cannot present an operator credential, and only the RECEIVING is open: reading what was '
    + 'received requires one like everything else here. Captures are held in memory, capped, rate '
    + 'limited per address so nobody can push a genuine capture out of the window, and any '
    + 'credential-bearing header is truncated before the capture leaves this process.',
  security: [],
  response: {
    200: {
      description: 'Received and recorded.',
      type: 'object',
      additionalProperties: false,
      required: ['received', 'id'],
      properties: {
        received: { type: 'boolean' },
        id: { type: 'string' },
      },
      examples: [{ received: true, id: '7c1f2c2a-6a1a-4d0f-9b0f-2b0f6b1a5e21' }],
    },
    413: { $ref: 'Problem#', description: 'The delivery was larger than the receiver accepts.' },
    429: { $ref: 'Problem#', description: 'Too many deliveries from this address.' },
  },
});

export async function deliveryInspectorController(fastify: FastifyInstance) {

  async function receive(request: FastifyRequest, reply: FastifyReply) {
    if (!receiverAllows(request.ip ?? 'unknown')) {
      reply.header('Retry-After', '60');
      return reply.status(429).send(problem(429, 'Too Many Requests', 'The inspector accepts fewer deliveries than that.'));
    }
    const id = uuidv4();
    const response = { received: true, id };
    const entry: DeliveryEntry = {
      id,
      method: request.method,
      path: request.url,
      query: (request.query as Record<string, string>) ?? {},
      headers: redactHeaders(request.headers as Record<string, unknown>),
      body: request.body ?? null,
      timestamp: new Date().toISOString(),
      ip: request.ip,
      response: { status: 200, body: response },
    };
    if (entries.length >= MAX_ENTRIES) entries.shift();
    entries.push(entry);
    broadcast('request', JSON.stringify(entry));
    return reply.status(200).send(response);
  }

  // One registration per method, so each carries its own identifier in the contract. A single route
  // with a method list would document five operations under one name and collide in a generated client.
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const) {
    fastify.route({
      method,
      url: '/hook',
      schema: receiverSchema(method),
      handler: receive,
    });
  }

  fastify.get('/stream', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'streamDeliveries',
      tags: ['admin'],
      summary: 'Watch deliveries as they arrive',
      description:
        `${NO_STANDARD} Replays what is held, then sends each new delivery as it lands. A comment `
        + 'frame every fifteen silent seconds keeps a proxy from dropping an idle stream, which would '
        + 'leave the panel showing nothing arriving when nothing was being forwarded.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'The delivery stream. Frames are `request`, `clear` and `delete`.',
          content: {
            'text/event-stream': {
              schema: {
                type: 'string',
                examples: ['event: request\ndata: {"text":"{\\"id\\":\\"7c1f2c2a\\"}"}\n\n'],
              },
            },
          },
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const raw = beginSSE(reply, request);
    // Without this a lone frame sits in the socket buffer until the next write, so a delivery only
    // appears when the following one arrives and the panel looks a minute behind the world.
    raw.socket?.setNoDelay(true);
    // Padding pushes the response past an intermediary's initial read threshold, so the first real
    // frames flush promptly instead of waiting for the buffer to fill.
    raw.write(`: connected${' '.repeat(2048)}\n\n`);

    for (const entry of entries) {
      raw.write(`event: request\ndata: ${JSON.stringify({ text: JSON.stringify(entry) })}\n\n`);
    }
    watchers.add(raw);

    const heartbeat = setInterval(() => {
      try { raw.write(SSE_HEARTBEAT_FRAME); } catch { /* socket gone, cleanup runs on close */ }
    }, SSE_HEARTBEAT_MS);

    const cleanup = () => { clearInterval(heartbeat); watchers.delete(raw); };
    raw.on('close', cleanup);
    request.raw.on('close', cleanup);
  });

  fastify.delete('/requests', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'clearDeliveries',
      tags: ['admin'],
      summary: 'Discard every captured delivery',
      description:
        `${NO_STANDARD} Empties what the inspector holds and tells every watcher, so two operators `
        + 'looking at the same panel do not disagree about what is there.',
      security: [{ bearerAuth: [] }],
      response: {
        200: {
          description: 'Discarded.',
          type: 'object',
          additionalProperties: false,
          required: ['cleared'],
          properties: { cleared: { type: 'boolean' } },
          examples: [{ cleared: true }],
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (_request, reply) => {
    entries.length = 0;
    broadcast('clear', '');
    return reply.send({ cleared: true });
  });

  fastify.delete<{ Params: { id: string } }>('/requests/:id', {
    preHandler: requireAdmin,
    schema: {
      operationId: 'deleteDelivery',
      tags: ['admin'],
      summary: 'Discard one captured delivery',
      description: `${NO_STANDARD} Removes one capture and tells every watcher it has gone.`,
      security: [{ bearerAuth: [] }],
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string', examples: ['7c1f2c2a-6a1a-4d0f-9b0f-2b0f6b1a5e21'] } },
      },
      response: {
        200: {
          description: 'Discarded.',
          type: 'object',
          additionalProperties: false,
          required: ['deleted'],
          properties: { deleted: { type: 'boolean' } },
          examples: [{ deleted: true }],
        },
        401: { $ref: 'Problem#', description: 'No valid operator credential.' },
        404: { $ref: 'Problem#', description: 'No capture with that identifier is held.' },
        503: { $ref: 'Problem#', description: 'The operations surface is not configured.' },
      },
    },
  }, async (request, reply) => {
    const index = entries.findIndex((entry) => entry.id === request.params.id);
    if (index === -1) return reply.status(404).send(problem(404, 'Not Found', 'No capture with that identifier.'));
    entries.splice(index, 1);
    broadcast('delete', request.params.id);
    return reply.send({ deleted: true });
  });

  fastify.addHook('onClose', async () => {
    for (const watcher of [...watchers]) {
      try { watcher.end(); } catch { /* already gone */ }
    }
    watchers.clear();
  });
}

/** Recorded when the inspector is registered, so its presence is visible in the log. */
export function noteInspectorReady(mountPath: string): void {
  appendLog(`[${new Date().toISOString()}] STARTUP delivery inspector receiving at ${mountPath}/hook`);
}
