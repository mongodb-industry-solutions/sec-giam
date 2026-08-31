// Ring buffer of recent GIAM log lines, read by the administration console over /admin/logs.
//
// Per-process state by nature, so it is GIAM's own rather than a shared module: sharing the
// implementation would still need one instance per service, and every failure path has to reach it or
// the console shows a healthy service that is not.
const MAX_LINES = 500;
const lines: string[] = [];
let consoleMirrored = false;

export function appendLog(line: string): void {
  lines.push(line);
  if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
}

export function levelLabel(level: number): string {
  if (level >= 60) return 'FATAL';
  if (level >= 50) return 'ERROR';
  if (level >= 40) return 'WARN';
  return 'INFO';
}

// A capped message, never a full stack: a stack from an identity service can carry a credential.
export function appendLogEntry(label: string, args: unknown[]): void {
  const parts = args.map((a) => {
    if (typeof a === 'string') return a;
    if (a instanceof Error) return `${a.name}: ${a.message}`;
    try { return JSON.stringify(a); } catch { return String(a); }
  });
  appendLog(`[${new Date().toISOString()}] ${label} ${parts.join(' ').replace(/\s+/g, ' ').slice(0, 500)}`);
}

export function readLogs(limit = MAX_LINES): string[] {
  return lines.slice(-limit);
}

// Background subsystems report through console.*, which bypasses the fastify logger entirely.
export function mirrorConsoleToLogBuffer(): void {
  if (consoleMirrored) return;
  consoleMirrored = true;
  for (const [method, label] of [['warn', 'WARN'], ['error', 'ERROR']] as const) {
    const original = console[method].bind(console);
    console[method] = (...args: unknown[]) => {
      appendLogEntry(label, args);
      original(...args);
    };
  }
}
