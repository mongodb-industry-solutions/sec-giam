import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ServerResponse } from 'http';
import { config } from '../../config';

/**
 * Server-sent streaming for the operations console.
 *
 * Hijacking the reply bypasses every Fastify plugin that would otherwise run on the way out, CORS
 * included, so the headers a browser needs are written here explicitly. Getting that wrong produces a
 * stream that works from the API's own origin and fails silently from the console's.
 *
 * Every stream built on this MUST keep sending. An ingress drops a connection that goes quiet, the
 * browser never receives the terminating frame, and the panel waits forever on a run that finished
 * minutes ago. The heartbeat is not a nicety, it is the difference between a console and a hang.
 */

function allowedOrigins(): string[] {
  const configured = (config.server.corsOrigin ?? '').trim();
  const origins = configured === '*' ? [] : configured.split(',').map((o) => o.trim()).filter(Boolean);
  if (origins.length === 0) origins.push(config.server.frontendUrl);
  return origins;
}

/**
 * The origin to echo back on a hijacked stream.
 *
 * A credentialed response cannot answer `*`, so a wildcard configuration reflects the caller's own
 * origin and anything else is matched against the configured list.
 */
export function resolveSSEOrigin(requestOrigin: string | undefined): string {
  const configured = (config.server.corsOrigin ?? '').trim();
  const origins = allowedOrigins();
  if (requestOrigin && (configured === '*' || origins.includes(requestOrigin))) return requestOrigin;
  return origins[0];
}

export function sseHeaders(requestOrigin: string | undefined): Record<string, string> {
  return {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    // Tells an nginx-family proxy not to buffer, which would hold every frame until the run ended.
    'X-Accel-Buffering': 'no',
    'Access-Control-Allow-Origin': resolveSSEOrigin(requestOrigin),
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}

/** Hijacks the reply, writes the stream headers, and hands back the raw socket. */
export function beginSSE(reply: FastifyReply, request: FastifyRequest): ServerResponse {
  reply.hijack();
  const raw = reply.raw;
  raw.writeHead(200, sseHeaders(request.headers.origin as string | undefined));
  raw.flushHeaders();
  return raw;
}

/** How often a stream must say something, whether or not it has anything to say. */
export const SSE_HEARTBEAT_MS = 15000;

/** A comment frame. It carries no event, so a client ignores it and a proxy sees traffic. */
export const SSE_HEARTBEAT_FRAME = ': ping\n\n';
