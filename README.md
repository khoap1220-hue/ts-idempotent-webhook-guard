# 🟦 ts-idempotent-webhook-guard (v1.1.0)

[![Tests](https://img.shields.io/badge/Tests-6%2F6_Passing-2ea44f?logo=nodedotjs)](test/guard.test.mjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_ESM-3178C6?logo=typescript)](src/index.d.ts)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/ts-idempotent-webhook-guard/commits/main)

**`ts-idempotent-webhook-guard`** is a zero-dependency TypeScript/ESM toolkit + CLI designed for **FinTech payment gateways, Stellar/Web3 streaming protocols, and webhook receivers**. It prevents race-condition double-spends on concurrent `Promise.all` requests, persists idempotency keys across restarts via an **Append-Only JSONL Write-Ahead Log (`FileWalIdempotencyStore`)**, verifies **HMAC-SHA256 & Stripe replay-window signatures** in constant time, enforces SSRF-safe `https://` URLs, and scrubs secrets/JWTs/PAN cards from logs.

---

## ✨ Core Modules

1. **`IdempotencyGuard` + `FileWalIdempotencyStore`:** Atomic in-flight promise coalescing + durable JSONL WAL persistence ensuring burst duplicate requests (`Promise.all`) and post-restart webhook replays execute ledger mutations **at most once**.
2. **Constant-Time Cryptographic Verification (`verifyHmacSha256Signature`, `verifyStripeSignatureHeader`, `verifyTimingSafeToken`):** Built on `node:crypto` (`timingSafeEqual`, `createHmac`) with timestamp tolerance checks (`t=...,v1=...`) to block replay and timing side-channel attacks.
3. **SSRF-Safe Endpoint Validator (`validateWebhookUrl`):** Rejects non-HTTPS schemes, embedded URL credentials, IPv4-mapped IPv6 loopback (`[::ffff:127.0.0.1]`), IPv6 unique-local (`fc00::/7`), and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
4. **Cycle-Safe DLP Redactor (`redactSensitiveFields`):** Recursively masks sensitive keys, Bearer/JWT tokens, and Luhn-valid payment card numbers while handling circular references (`WeakSet`).

---

## 🚀 Library & CLI Quickstart

```ts
import {
  FileWalIdempotencyStore,
  IdempotencyGuard,
  verifyStripeSignatureHeader,
  validateWebhookUrl,
  redactSensitiveFields,
} from "ts-idempotent-webhook-guard";

const store = new FileWalIdempotencyStore("./data/webhook-idempotency.wal.jsonl");
const guard = new IdempotencyGuard({ ttlMs: 300_000, store });

const { result, replayed } = await guard.execute("payment-ref-2026-01", async () => {
  return { status: "credited", amountUsdc: 100 };
});
```

### CLI Usage

```bash
node ./bin/webhook-guard.mjs validate-url "https://hooks.stellar-app.io/v1/events"
node ./bin/webhook-guard.mjs sign-hmac "whsec_secret" '{"id":"evt_1"}' 1762000000
```

## 🧪 Running Tests

```bash
npm test
```

## 📄 License

Released under the [MIT License](LICENSE).
