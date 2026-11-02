import test from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  FileWalIdempotencyStore,
  IdempotencyGuard,
  computeHmacSha256Hex,
  redactSensitiveFields,
  validateWebhookUrl,
  verifyHmacSha256Signature,
  verifyStripeSignatureHeader,
  verifyTimingSafeToken,
} from "../src/index.mjs";

test("IdempotencyGuard deduplicates concurrent Promise.all requests and executes handler exactly once", async () => {
  const guard = new IdempotencyGuard({ ttlMs: 60_000 });
  let executionCount = 0;

  const slowPaymentMutation = async () => {
    executionCount += 1;
    await new Promise((resolve) => setTimeout(resolve, 25));
    return { txId: "TX-9001", amountUsd: 150 };
  };

  const responses = await Promise.all([
    guard.execute("order-7788", slowPaymentMutation),
    guard.execute("order-7788", slowPaymentMutation),
    guard.execute("order-7788", slowPaymentMutation),
  ]);

  assert.equal(executionCount, 1, "handler must execute exactly once under concurrency");
  const freshCount = responses.filter((r) => !r.replayed).length;
  const replayedCount = responses.filter((r) => r.replayed).length;
  assert.equal(freshCount, 1);
  assert.equal(replayedCount, 2);
  assert.deepEqual(responses[0].result, { txId: "TX-9001", amountUsd: 150 });
});

test("FileWalIdempotencyStore persists idempotency records across process restarts and compacts expired keys", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "wal-guard-"));
  const walFile = path.join(tmpDir, "idempotency.wal.jsonl");

  const store1 = new FileWalIdempotencyStore(walFile);
  const guard1 = new IdempotencyGuard({ ttlMs: 60_000, store: store1 });
  let calls = 0;
  const firstRun = await guard1.execute("sepay-ref-10099", async () => {
    calls += 1;
    return { creditedVnd: 500_000 };
  });
  assert.equal(firstRun.replayed, false);
  assert.equal(calls, 1);

  // Simulate process restart by instantiating a brand new store & guard pointing to the same WAL file
  const store2 = new FileWalIdempotencyStore(walFile);
  const guard2 = new IdempotencyGuard({ ttlMs: 60_000, store: store2 });
  assert.equal(guard2.has("sepay-ref-10099"), true);
  const secondRun = await guard2.execute("sepay-ref-10099", async () => {
    calls += 1;
    return { creditedVnd: 999_999 };
  });
  assert.equal(secondRun.replayed, true, "restarted guard must replay from disk WAL");
  assert.equal(calls, 1, "handler must not re-run after restart");
  assert.deepEqual(secondRun.result, { creditedVnd: 500_000 });

  const retained = store2.compact();
  assert.equal(retained, 1);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("verifyHmacSha256Signature and verifyStripeSignatureHeader enforce HMAC integrity and replay windows", () => {
  const secret = "whsec_test_secret_key_2026";
  const body = JSON.stringify({ id: "evt_01", amount: 2500 });
  const sig = computeHmacSha256Hex(body, secret);

  assert.equal(verifyHmacSha256Signature(body, `sha256=${sig}`, secret), true);
  assert.equal(verifyHmacSha256Signature(body, `sha256=${sig}`, "wrong_secret"), false);

  const nowSec = 1_762_000_000;
  const stripeSig = computeHmacSha256Hex(`${nowSec}.${body}`, secret);
  const header = `t=${nowSec},v1=${stripeSig}`;

  const okRes = verifyStripeSignatureHeader(body, header, secret, {
    nowSeconds: nowSec + 45,
    toleranceSeconds: 300,
  });
  assert.equal(okRes.valid, true);

  const replayRes = verifyStripeSignatureHeader(body, header, secret, {
    nowSeconds: nowSec + 600,
    toleranceSeconds: 300,
  });
  assert.equal(replayRes.valid, false);
  assert.match(replayRes.reason || "", /replay tolerance/i);
});

test("verifyTimingSafeToken performs constant-time Bearer and Apikey comparisons", () => {
  assert.equal(verifyTimingSafeToken("Bearer sepay_live_key_99", "sepay_live_key_99"), true);
  assert.equal(verifyTimingSafeToken("Apikey sepay_live_key_99", "sepay_live_key_99"), true);
  assert.equal(verifyTimingSafeToken("Bearer wrong_length", "sepay_live_key_99"), false);
  assert.equal(verifyTimingSafeToken("", "sepay_live_key_99"), false);
});

test("validateWebhookUrl enforces HTTPS and blocks IPv4/IPv6 SSRF loopback & metadata targets", () => {
  assert.equal(validateWebhookUrl("http://example.com/webhook").valid, false);
  assert.equal(validateWebhookUrl("https://127.0.0.1/hook").valid, false);
  assert.equal(validateWebhookUrl("https://admin.localhost/hook").valid, false);
  assert.equal(validateWebhookUrl("https://service.internal/hook").valid, false);
  assert.equal(validateWebhookUrl("https://[::ffff:127.0.0.1]/hook").valid, false);
  assert.equal(validateWebhookUrl("https://[::ffff:172.16.0.1]/hook").valid, false);
  assert.equal(validateWebhookUrl("https://[::ffff:0.0.0.0]/hook").valid, false);
  assert.equal(validateWebhookUrl("https://[0:0:0:0:0:0:0:1]/hook").valid, false);
  assert.equal(validateWebhookUrl("https://[fd00::1]/hook").valid, false);
  assert.equal(validateWebhookUrl("https://metadata.google.internal/computeMetadata/v1/").valid, false);
  assert.equal(validateWebhookUrl("https://user:pass@api.example.com/hook").valid, false);

  const ok = validateWebhookUrl("https://hooks.stellar-app.io/v1/events");
  assert.equal(ok.valid, true);
  assert.equal(ok.normalizedUrl, "https://hooks.stellar-app.io/v1/events");
});

test("redactSensitiveFields scrubs nested secrets, JWTs, Luhn PAN cards, and circular objects", () => {
  const rawLog = {
    requestId: "req-1",
    headers: {
      Authorization: "Bearer secret-jwt-token-123",
      "x-api-key": "sk_live_999999",
    },
    note: "Token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c and card 4532 0151 1283 0366 seen",
  };
  rawLog.self = rawLog;

  const sanitized = redactSensitiveFields(rawLog);
  assert.equal(sanitized.headers.Authorization, "[REDACTED_SECRET]");
  assert.equal(sanitized.headers["x-api-key"], "[REDACTED_SECRET]");
  assert.ok(sanitized.note.includes("[REDACTED_TOKEN]"));
  assert.ok(sanitized.note.includes("[REDACTED_CARD_0366]"));
  assert.equal(sanitized.self, "[CIRCULAR_REF]");
});
