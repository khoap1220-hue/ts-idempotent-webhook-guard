/**
 * ts-idempotent-webhook-guard (v1.1.0)
 * Zero-dependency concurrency-safe idempotency lock with durable File-Backed JSONL WAL,
 * constant-time HMAC-SHA256 & Stripe replay-window signature verifier, SSRF-safe HTTPS
 * endpoint validator, and cycle-safe recursive secret redactor for FinTech & Web3 backends.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

const PRIVATE_HOST_PATTERNS = [
  /(?:^|\.)localhost$/i,
  /\.local$/i,
  /(?:^|\.)internal$/i,
  /^127\./,
  /^0\./,
  /^10\./,
  /^192\.168\./,
  /^169\.254\./,
  /^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^\[(?:0+:){7}0*[01]\]$/i,
  /^\[::1?\]$/i,
  /^\[::ffff:(?:0+:0+|127\.|7f[0-9a-f]{2}:|0?a[0-9a-f]{2}:|ac1[0-9a-f]:|c0a8:|a9fe:|64(?:[4-7][0-9a-f]):)/i,
  /^\[f[cd][0-9a-f]{2}:/i,
  /^\[fe[89ab][0-9a-f]:/i,
];

const SENSITIVE_KEY_REGEX =
  /^(?:x-)?(authorization|api[-_]?key|secret|password|passwd|token|access[-_]?token|refresh[-_]?token|private[-_]?key|client[-_]?secret|webhook[-_]?secret|cvv|cvc|pin)$/i;
const BEARER_OR_JWT_REGEX =
  /(Bearer\s+[A-Za-z0-9._~+/-]+=*|Apikey\s+[A-Za-z0-9._~+/-]+=*|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})/gi;
const CARD_CANDIDATE_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

function passesLuhnCheck(digitsOnly) {
  if (digitsOnly.length < 13 || digitsOnly.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let digit = digitsOnly.charCodeAt(i) - 48;
    if (digit < 0 || digit > 9) return false;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum > 0 && sum % 10 === 0;
}

/**
 * Durable Append-Only JSONL Write-Ahead Log (WAL) store for idempotency keys.
 * Survives process restarts without external Redis dependencies.
 */
export class FileWalIdempotencyStore {
  /**
   * @param {string} filePath
   */
  constructor(filePath) {
    if (!filePath || typeof filePath !== "string") {
      throw new Error("FileWalIdempotencyStore requires a valid filePath string");
    }
    this.filePath = path.resolve(filePath);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  /**
   * Loads all non-expired idempotency records from the WAL file on disk.
   * @param {number} [now]
   * @returns {Map<string, { value: any, expiresAt: number }>}
   */
  loadActiveEntries(now = Date.now()) {
    const map = new Map();
    if (!fs.existsSync(this.filePath)) {
      return map;
    }
    const content = fs.readFileSync(this.filePath, "utf8");
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed.key === "string" && typeof parsed.expiresAt === "number") {
          if (parsed.expiresAt > now) {
            map.set(parsed.key, { value: parsed.value, expiresAt: parsed.expiresAt });
          } else {
            map.delete(parsed.key);
          }
        }
      } catch {
        // Ignore truncated trailing line from a prior crash
      }
    }
    return map;
  }

  /**
   * Appends a completed idempotency record atomically to the WAL file.
   * @param {string} key
   * @param {{ value: any, expiresAt: number }} entry
   */
  appendEntry(key, entry) {
    const record = JSON.stringify({
      key,
      value: entry.value,
      expiresAt: entry.expiresAt,
      recordedAt: Date.now(),
    });
    fs.appendFileSync(this.filePath, record + "\n", "utf8");
  }

  /**
   * Rewrites the WAL file retaining only currently unexpired records.
   * @param {number} [now]
   * @returns {number} Number of active records retained
   */
  compact(now = Date.now()) {
    const active = this.loadActiveEntries(now);
    const tmpPath = `${this.filePath}.tmp.${process.pid}`;
    const lines = [];
    for (const [key, entry] of active.entries()) {
      lines.push(JSON.stringify({ key, value: entry.value, expiresAt: entry.expiresAt }));
    }
    fs.writeFileSync(tmpPath, lines.length > 0 ? lines.join("\n") + "\n" : "", "utf8");
    fs.renameSync(tmpPath, this.filePath);
    return active.size;
  }
}

/**
 * Concurrency-safe Idempotency Guard ensuring simultaneous requests with the same
 * idempotency key execute the underlying mutation handler at most once.
 */
export class IdempotencyGuard {
  /**
   * @param {{ ttlMs?: number, maxEntries?: number, store?: FileWalIdempotencyStore }} [options]
   */
  constructor(options = {}) {
    this.ttlMs = options.ttlMs ?? 300_000;
    this.maxEntries = options.maxEntries ?? 10_000;
    this.store = options.store ?? null;
    /** @type {Map<string, { value: any, expiresAt: number }>} */
    this.completed = this.store ? this.store.loadActiveEntries() : new Map();
    /** @type {Map<string, Promise<any>>} */
    this.inFlight = new Map();
  }

  /**
   * Checks whether `key` has already been processed and has not expired.
   * @param {string} key
   * @returns {boolean}
   */
  has(key) {
    if (!key || typeof key !== "string") return false;
    const normalizedKey = key.trim();
    const cached = this.completed.get(normalizedKey);
    if (!cached) return false;
    if (cached.expiresAt <= Date.now()) {
      this.completed.delete(normalizedKey);
      return false;
    }
    return true;
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
    if (cached) {
      if (cached.expiresAt > now) {
        return { result: cached.value, replayed: true };
      }
      this.completed.delete(normalizedKey);
    }

    const existingPromise = this.inFlight.get(normalizedKey);
    if (existingPromise) {
      const sharedResult = await existingPromise;
      return { result: sharedResult, replayed: true };
    }

    const executionPromise = (async () => {
      try {
        const value = await handler();
        const entry = {
          value,
          expiresAt: Date.now() + this.ttlMs,
        };
        if (this.completed.size >= this.maxEntries) {
          const oldestKey = this.completed.keys().next().value;
          if (oldestKey !== undefined) {
            this.completed.delete(oldestKey);
          }
        }
        this.completed.set(normalizedKey, entry);
        if (this.store) {
          this.store.appendEntry(normalizedKey, entry);
        }
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
 * Compares a provided API key or Authorization header (`Bearer <token>` / `Apikey <token>`)
 * against `expectedSecret` in constant time using `crypto.timingSafeEqual`.
 *
 * @param {string | undefined | null} providedHeaderOrToken
 * @param {string | undefined | null} expectedSecret
 * @returns {boolean}
 */
export function verifyTimingSafeToken(providedHeaderOrToken, expectedSecret) {
  if (typeof providedHeaderOrToken !== "string" || typeof expectedSecret !== "string") {
    return false;
  }
  const cleanExpected = expectedSecret.trim();
  if (!cleanExpected) return false;
  const cleanProvided = providedHeaderOrToken.replace(/^(?:Bearer|Apikey)\s+/i, "").trim();
  if (!cleanProvided) return false;

  const bufA = Buffer.from(cleanProvided, "utf8");
  const bufB = Buffer.from(cleanExpected, "utf8");
  if (bufA.length !== bufB.length) {
    // Hash both to 32 bytes so execution time does not leak expectedSecret byte length
    const dA = crypto.createHash("sha256").update(bufA).digest();
    const dB = crypto.createHash("sha256").update(bufB).digest();
    crypto.timingSafeEqual(dA, dB);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Computes an HMAC-SHA256 hex signature over `rawBody`.
 *
 * @param {string | Buffer} rawBody
 * @param {string} secret
 * @returns {string}
 */
export function computeHmacSha256Hex(rawBody, secret) {
  if (!secret || typeof secret !== "string") {
    throw new Error("Webhook HMAC secret must be a non-empty string");
  }
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

/**
 * Verifies an HMAC-SHA256 webhook signature header (e.g. `sha256=<hex>` or raw `<hex>`)
 * using constant-time comparison.
 *
 * @param {string | Buffer} rawBody
 * @param {string | undefined | null} signatureHeader
 * @param {string} secret
 * @returns {boolean}
 */
export function verifyHmacSha256Signature(rawBody, signatureHeader, secret) {
  if (typeof signatureHeader !== "string" || !signatureHeader.trim() || !secret) {
    return false;
  }
  const providedHex = signatureHeader.trim().replace(/^sha256=/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(providedHex)) {
    return false;
  }
  const expectedHex = computeHmacSha256Hex(rawBody, secret);
  return crypto.timingSafeEqual(
    Buffer.from(providedHex.toLowerCase(), "hex"),
    Buffer.from(expectedHex.toLowerCase(), "hex")
  );
}

/**
 * Verifies a timestamped Stripe-style webhook signature (`t=<unix_sec>,v1=<hex>`)
 * and enforces a bounded replay window (`toleranceSeconds`, default 300s).
 *
 * @param {string | Buffer} rawBody
 * @param {string | undefined | null} stripeHeader
 * @param {string} secret
 * @param {{ toleranceSeconds?: number, nowSeconds?: number }} [options]
 * @returns {{ valid: boolean, reason?: string, timestamp?: number }}
 */
export function verifyStripeSignatureHeader(rawBody, stripeHeader, secret, options = {}) {
  if (typeof stripeHeader !== "string" || !stripeHeader.trim()) {
    return { valid: false, reason: "Missing Stripe-Signature header" };
  }
  if (!secret || typeof secret !== "string") {
    return { valid: false, reason: "Missing webhook signing secret" };
  }

  let timestamp = NaN;
  /** @type {string[]} */
  const v1Signatures = [];
  for (const part of stripeHeader.split(",")) {
    const [k, v] = part.trim().split("=", 2);
    if (k === "t" && v) {
      timestamp = Number(v);
    } else if (k === "v1" && v) {
      v1Signatures.push(v.trim());
    }
  }

  if (!Number.isInteger(timestamp) || timestamp <= 0 || v1Signatures.length === 0) {
    return { valid: false, reason: "Malformed Stripe-Signature header (missing integer t or v1)" };
  }

  const tolerance = options.toleranceSeconds ?? 300;
  const nowSec = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestamp) > tolerance) {
    return { valid: false, reason: "Webhook timestamp outside replay tolerance window", timestamp };
  }

  const bodyStr = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : String(rawBody);
  const signedPayload = `${timestamp}.${bodyStr}`;
  const expectedHex = computeHmacSha256Hex(signedPayload, secret);
  const expectedBuf = Buffer.from(expectedHex, "hex");

  for (const cand of v1Signatures) {
    if (/^[0-9a-fA-F]{64}$/.test(cand)) {
      const candBuf = Buffer.from(cand.toLowerCase(), "hex");
      if (candBuf.length === expectedBuf.length && crypto.timingSafeEqual(candBuf, expectedBuf)) {
        return { valid: true, timestamp };
      }
    }
  }
  return { valid: false, reason: "Signature mismatch", timestamp };
}

/**
 * Validates that a webhook target URL strictly uses `https:` and does not point to
 * loopback, link-local, cloud metadata, or RFC1918/IPv6 private networks (SSRF protection).
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
    return { valid: false, reason: "Private, loopback, or metadata hostnames are not permitted" };
  }

  return { valid: true, normalizedUrl: parsed.toString() };
}

function maskStringSecrets(text) {
  const tokenScrubbed = text.replace(BEARER_OR_JWT_REGEX, "[REDACTED_TOKEN]");
  return tokenScrubbed.replace(CARD_CANDIDATE_REGEX, (match) => {
    const digits = match.replace(/\D/g, "");
    if (passesLuhnCheck(digits)) {
      return `[REDACTED_CARD_${digits.slice(-4)}]`;
    }
    return match;
  });
}

/**
 * Deeply clones and redacts sensitive keys, Bearer/JWT tokens, and Luhn-valid payment cards
 * from log payloads while safely handling circular object references.
 *
 * @param {any} payload
 * @param {WeakSet<object>} [seen]
 * @returns {any}
 */
export function redactSensitiveFields(payload, seen = new WeakSet()) {
  if (payload === null || payload === undefined) {
    return payload;
  }
  if (typeof payload === "string") {
    return maskStringSecrets(payload);
  }
  if (typeof payload !== "object") {
    return payload;
  }
  if (seen.has(payload)) {
    return "[CIRCULAR_REF]";
  }
  seen.add(payload);

  if (Array.isArray(payload)) {
    return payload.map((item) => redactSensitiveFields(item, seen));
  }

  /** @type {Record<string, any>} */
  const out = {};
  for (const [k, v] of Object.entries(payload)) {
    if (SENSITIVE_KEY_REGEX.test(k)) {
      out[k] = "[REDACTED_SECRET]";
    } else {
      out[k] = redactSensitiveFields(v, seen);
    }
  }
  return out;
}

/**
 * Compacts a JSONL Write-Ahead Log file by keeping only the latest valid entry per key.
 * @param {string} walPath
 * @returns {number} Number of unique retained keys
 */
export function compactWalFile(walPath) {
  if (!fs.existsSync(walPath)) return 0;
  const raw = fs.readFileSync(walPath, "utf8");
  const latest = new Map();
  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const obj = JSON.parse(line);
      if (obj && typeof obj.key === "string") latest.set(obj.key, obj);
    } catch {}
  }
  const compacted = Array.from(latest.values()).map((v) => JSON.stringify(v)).join("\n") + (latest.size ? "\n" : "");
  fs.writeFileSync(walPath, compacted, "utf8");
  return latest.size;
}
