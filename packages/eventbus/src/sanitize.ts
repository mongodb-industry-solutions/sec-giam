// Cardholder-data (CHD) scrubbing: the canonical PCI DSS boundary, owned by the eventbus
// vendor so every publisher/logger shares ONE blocklist (no duplication, single source of truth).
// Keys are stripped at ANY nesting depth before an event/payload is persisted or delivered.

export const CHD_BLOCKLIST = new Set([
  'pan', 'cardNumber', 'cvv', 'cvv2', 'cvc', 'cvc2',
  'expiryDate', 'cardExpiry', 'expiry', 'cardholderName',
  'trackData', 'track1', 'track2', 'track3', 'pinBlock',
  'fullCardNumber', 'primaryAccountNumber',
]);

/** Shallow scrub: drops blocklisted top-level keys. */
export function sanitizeSummary(raw: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(raw).filter(([k]) => !CHD_BLOCKLIST.has(k)));
}

/** Deep scrub: drops blocklisted keys at any depth (payloads can nest, e.g. card.cvv). */
export function sanitizeDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitizeDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([k]) => !CHD_BLOCKLIST.has(k))
        .map(([k, v]) => [k, sanitizeDeep(v)]),
    );
  }
  return value;
}

// OAuth/OIDC secrets and PII that must never reach a log or an audit event (PCI DSS, GDPR).
// Distinct from CHD (above): these are credentials/tokens, not cardholder data. Keys are
// matched case-insensitively. `state`/`nonce` are intentionally NOT blocklisted (callers must hash
// them before logging, never log the raw value).
export const SECRET_BLOCKLIST = new Set([
  'access_token', 'refresh_token', 'id_token', 'token',
  'code', 'code_verifier', 'authorization_code',
  'client_secret', 'secret', 'password',
  'authorization', 'cookie', 'set-cookie',
  'email', 'phone', 'phone_number',
]);

/** Deep scrub for logs/audit: strips CHD AND OAuth secrets/PII at any depth. */
export function redactSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactSecrets);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([k]) => !CHD_BLOCKLIST.has(k) && !SECRET_BLOCKLIST.has(k.toLowerCase()))
        .map(([k, v]) => [k, redactSecrets(v)]),
    );
  }
  return value;
}
