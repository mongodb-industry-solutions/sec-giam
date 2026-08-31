// Reconciles the operator's stored monitoring config with the shipped defaults.
//
// Two problems this solves, both of which were live bugs. A newly shipped service never reached an
// operator who already had a stored config, because defaults were only read when storage was empty.
// And when a shipped service MOVED (the health aliases became /health/<service>), the stored copy kept
// the old path and reported the service as unreachable, which looks exactly like an outage.
//
// The split of ownership is what keeps both fixable without fighting the operator:
//   · the shipped file owns HOW to reach a service (url, transport, labels), because the platform is
//     what moves an endpoint, and an operator pinning a stale path is never what they meant;
//   · the operator owns THEIR tuning (enabled, intervals, timeout, expected status).
// An operator who genuinely wants a different target adds their own service with its own id, and
// nothing here touches it.

export interface MonitoringServiceShape {
  id: string;
  name: string;
  description: string;
  type: string;
  url: string;
  detailUrl?: string;
  method: string;
  enabled: boolean;
  intervalMs: number;
  timeoutMs: number;
  expectedStatus: number;
  useApiBase: boolean;
}

// Fields the shipped defaults own. Everything else is the operator's.
const SHIPPED_FIELDS = ['name', 'description', 'type', 'url', 'detailUrl', 'method', 'useApiBase'] as const;

export interface MergeResult<T extends MonitoringServiceShape> {
  services: T[];
  // True when anything changed, so the caller only writes to storage when it must.
  changed: boolean;
  // Ids of every shipped default, for the "already offered" record.
  defaultIds: string[];
}

export function mergeMonitoringDefaults<T extends MonitoringServiceShape>(
  stored: T[],
  defaults: T[],
  knownDefaultIds: string[],
): MergeResult<T> {
  const defaultIds = defaults.map((d) => d.id);
  if (stored.length === 0) {
    return { services: defaults, changed: defaults.length > 0, defaultIds };
  }

  const byId = new Map(defaults.map((d) => [d.id, d]));
  let changed = false;

  const refreshed = stored.map((service) => {
    const shipped = byId.get(service.id);
    if (!shipped) return service;
    const next = { ...service };
    for (const field of SHIPPED_FIELDS) {
      if (shipped[field] !== service[field]) {
        (next as Record<string, unknown>)[field] = shipped[field];
        changed = true;
      }
    }
    return next;
  });

  // Adopt shipped services this browser has never been offered. One that was offered and then removed
  // stays removed: re-adding it on every load would override a deliberate decision.
  const present = new Set(stored.map((s) => s.id));
  const adopted = defaults.filter((d) => !present.has(d.id) && !knownDefaultIds.includes(d.id));
  if (adopted.length > 0) changed = true;

  return { services: [...refreshed, ...adopted], changed, defaultIds };
}
