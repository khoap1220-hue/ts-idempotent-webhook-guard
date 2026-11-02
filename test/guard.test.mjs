import test from "node:test";
import assert from "node:assert/strict";
import {
  IdempotencyGuard,
  validateWebhookUrl,
  redactSensitiveFields,
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

test("validateWebhookUrl enforces HTTPS and blocks SSRF loopback/private hosts", () => {
  assert.equal(validateWebhookUrl("http://example.com/webhook").valid, false);
  assert.equal(validateWebhookUrl("https://127.0.0.1/hook").valid, false);
  assert.equal(validateWebhookUrl("https://user:pass@api.example.com/hook").valid, false);

  const ok = validateWebhookUrl("https://hooks.stellar-app.io/v1/events");
  assert.equal(ok.valid, true);
  assert.equal(ok.normalizedUrl, "https://hooks.stellar-app.io/v1/events");
});

test("redactSensitiveFields scrubs nested secrets and Bearer JWTs", () => {
  const rawLog = {
    requestId: "req-1",
    headers: {
      Authorization: "Bearer secret-jwt-token-123",
      "x-api-key": "sk_live_999999",
    },
    note: "Token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c seen",
  };

  const sanitized = redactSensitiveFields(rawLog);
  assert.equal(sanitized.headers.Authorization, "[REDACTED_SECRET]");
  assert.equal(sanitized.headers["x-api-key"], "[REDACTED_SECRET]");
  assert.ok(sanitized.note.includes("[REDACTED_TOKEN]"));
});
