/**
 * ts-idempotent-webhook-guard
 * Zero-dependency concurrency-safe idempotency lock, strict HTTPS validator,
 * and recursive secret redaction logger for FinTech & Web3 backends.
 */

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^\[::1\]$/,
];

const SENSITIVE_KEY_REGEX = /^(?:x-)?(authorization|api[-_]?key|secret|password|token|private[-_]?key|client[-_]?secret|cvv)$/i;
const BEARER_OR_JWT_REGEX = /(Bearer\s+[A-Za-z0-9._~+/-]+=*|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})/g;

/**
 * Concurrency-safe Idempotency Guard ensuring simultaneous requests with the same
 * idempotency key execute the underlying mutation handler at most once.
 */
export class IdempotencyGuard {
  /**
   * @param {{ ttlMs?: number }} [options]
   */
  constructor(options = {}) {
    this.ttlMs = options.ttlMs ?? 300_000;
    /** @type {Map<string, { value: any, expiresAt: number }>} */
    this.completed = new Map();
    /** @type {Map<string, Promise<any>>} */
    this.inFlight = new Map();
  }

  /**
   * Executes `handler` once per unique `key`. Concurrent callers awaiting the same
   * key receive the shared promise result with `replayed: true`.
   *
   * @template T
   * @param {string} key
   * @param {() => Promise<T>} handler
   * @returns {Promise<{ result: T, replayed: boolean }>}
   */
  async execute(key, handler) {
    if (!key || typeof key !== "string" || !key.trim()) {
      throw new Error("Idempotency key must be a non-empty string");
    }
    const normalizedKey = key.trim();
    const now = Date.now();

    const cached = this.completed.get(normalizedKey);
    if (cached && cached.expiresAt > now) {
      return { result: cached.value, replayed: true };
    }

    const existingPromise = this.inFlight.get(normalizedKey);
    if (existingPromise) {
      const sharedResult = await existingPromise;
      return { result: sharedResult, replayed: true };
    }

    const executionPromise = (async () => {
      try {
        const value = await handler();
        this.completed.set(normalizedKey, {
          value,
          expiresAt: Date.now() + this.ttlMs,
        });
        return value;
      } finally {
        this.inFlight.delete(normalizedKey);
      }
    })();

    this.inFlight.set(normalizedKey, executionPromise);
    const freshResult = await executionPromise;
    return { result: freshResult, replayed: false };
  }
}

/**
 * Validates that a webhook target URL strictly uses `https:` and does not point to
 * loopback, link-local, or RFC1918 private networks (SSRF protection).
 *
 * @param {string} rawUrl
 * @param {{ allowLocalhostHttps?: boolean }} [options]
 * @returns {{ valid: boolean, reason?: string, normalizedUrl?: string }}
 */
export function validateWebhookUrl(rawUrl, options = {}) {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    return { valid: false, reason: "Webhook URL is required" };
  }
  let parsed;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    return { valid: false, reason: "Malformed URL syntax" };
  }

  if (parsed.protocol !== "https:") {
    return { valid: false, reason: "Webhook URL must use https:// protocol" };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, reason: "Embedded credentials are not allowed in webhook URLs" };
  }

  const host = parsed.hostname;
  if (!options.allowLocalhostHttps && PRIVATE_HOST_PATTERNS.some((rx) => rx.test(host))) {
    return { valid: false, reason: "Private or loopback hostnames are not permitted" };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

/**
 * Deeply clones and redacts sensitive keys and Bearer/JWT tokens from log payloads.
 *
 * @param {any} payload
 * @returns {any}
 */
export function redactSensitiveFields(payload) {
  if (payload === null || payload === undefined) {
    return payload;
  }
  if (typeof payload === "string") {
    return payload.replace(BEARER_OR_JWT_REGEX, "[REDACTED_TOKEN]");
  }
  if (Array.isArray(payload)) {
    return payload.map((item) => redactSensitiveFields(item));
  }
  if (typeof payload === "object") {
    /** @type {Record<string, any>} */
    const out = {};
    for (const [k, v] of Object.entries(payload)) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        out[k] = "[REDACTED_SECRET]";
      } else {
        out[k] = redactSensitiveFields(v);
      }
    }
    return out;
  }
  return payload;
}
