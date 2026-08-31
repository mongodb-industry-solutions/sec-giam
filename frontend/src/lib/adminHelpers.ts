export const ADMIN_TOKEN_KEY = 'admin_token';

export function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export type LogEntry = { type: 'log' | 'error' | 'start' | 'done'; text: string };

/**
 * Normalized test result contract, emitted by /admin/run as a dedicated `summary`
 * SSE event (ADR-026). Produced server-side from each tool's native JSON reporter,
 * so the frontend renders it directly instead of parsing log text.
 */
export interface TestSummary {
  tool: 'vitest' | 'playwright' | 'all';
  total: number;
  passed: number;
  failed: number;
  skipped: number;
  durationMs: number;
  failures: Array<{ title: string; reason?: string }>;
}

// CLI tools (vitest, npm, tsc) emit ANSI color/control codes that render as noise
// in an HTML log viewer. Strip them so streamed output is human-readable.
// The leading character class matches the ESC and CSI escape introducers
// using unicode escapes, keeping the source free of literal control bytes.
const ANSI_RE = new RegExp(
  '[\\u001B\\u009B][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]',
  'g',
);

export function stripAnsi(text: string): string {
  return text.replace(ANSI_RE, '');
}

/**
 * Parse a response body as JSON without throwing on non-JSON payloads. While the backend
 * is restarting, the ingress/proxy answers with plain text ("no healthy upstream", HTML
 * error pages), which would otherwise surface as "Unexpected token 'o' ... is not valid JSON".
 * Returns the parsed object, or null plus the raw text when it is not JSON.
 */
export async function readJsonSafe<T>(res: Response): Promise<{ data: T | null; text: string }> {
  const text = await res.text().catch(() => '');
  if (!text) return { data: null, text: '' };
  try {
    return { data: JSON.parse(text) as T, text };
  } catch {
    return { data: null, text };
  }
}

/** True while a proxy/ingress reports no reachable backend (pod restarting, not an app error). */
export function isUpstreamUnavailable(res: Response): boolean {
  return res.status === 502 || res.status === 503 || res.status === 504;
}

export function getAdminToken(): string | null {
  if (typeof window === 'undefined') return null;
  return sessionStorage.getItem(ADMIN_TOKEN_KEY);
}

/**
 * Reads an SSE stream. `idleTimeoutMs` guards against a proxy that keeps the connection open but
 * stops forwarding bytes: without it a dropped stream leaves the caller awaiting read() forever
 * (the admin panel would spin with no way to finish). The server sends `: ping` comment frames
 * every 15s, so any silence longer than the timeout means the stream is really gone.
 */
export async function readSSE(
  res: Response,
  onEntry: (type: string, text: string) => void,
  onSummary?: (summary: TestSummary) => void,
  idleTimeoutMs = 0,
): Promise<void> {
  if (!res.body) return;
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const STALLED = Symbol('stalled');
  let buf = '';
  while (true) {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const next = idleTimeoutMs > 0
      ? await Promise.race([
          reader.read(),
          new Promise<typeof STALLED>((r) => { timer = setTimeout(() => r(STALLED), idleTimeoutMs); }),
        ])
      : await reader.read();
    if (timer) clearTimeout(timer);
    if (next === STALLED) {
      await reader.cancel().catch(() => { /* already gone */ });
      throw new Error(
        `Stream stalled: no output for ${Math.round(idleTimeoutMs / 1000)}s. The command may still be running on the server, check the Logs panel.`,
      );
    }
    const { done, value } = next;
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split('\n\n');
    buf = parts.pop() ?? '';
    for (const part of parts) {
      const eventLine = part.split('\n').find((l) => l.startsWith('event:'));
      const dataLine  = part.split('\n').find((l) => l.startsWith('data:'));
      if (!dataLine) continue;
      const type = eventLine?.slice(6).trim() ?? 'log';
      const dataStr = dataLine.slice(5).trim();
      try {
        // The `summary` frame carries the structured object directly; all other
        // frames carry { text } and feed the log console.
        if (type === 'summary') {
          onSummary?.(JSON.parse(dataStr) as TestSummary);
        } else {
          const { text } = JSON.parse(dataStr) as { text: string };
          onEntry(type, stripAnsi(text));
        }
      } catch { /* skip malformed frame */ }
    }
  }
}
