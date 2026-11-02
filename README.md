# 🟦 ts-idempotent-webhook-guard

[![Tests](https://img.shields.io/badge/Tests-3%2F3_Passing-2ea44f?logo=nodedotjs)](test/guard.test.mjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-Strict_ESM-3178C6?logo=typescript)](src/index.d.ts)
[![GPG Verified](https://img.shields.io/badge/Commits-GPG_Verified-2ea44f?logo=github)](https://github.com/khoap1220-hue/ts-idempotent-webhook-guard/commits/main)

**`ts-idempotent-webhook-guard`** is a zero-dependency TypeScript/ESM toolkit designed for **FinTech payment gateways, Stellar/Web3 streaming protocols, and webhook dispatchers**. It prevents race-condition double-spends on concurrent `Promise.all` requests, enforces strict `https://` SSRF-safe webhook URLs, and redacts secrets from request logs.

---

## ✨ Core Modules

- **`IdempotencyGuard`:** Atomic in-flight promise coalescing + TTL cache ensuring burst duplicate requests (`Promise.all`) execute the underlying billing/ledger mutation **exactly once**.
- **`validateWebhookUrl`:** Rejects non-HTTPS schemes, embedded URL credentials, and RFC1918/loopback SSRF targets.
- **`redactSensitiveFields`:** Recursively masks `Authorization`, `x-api-key`, `privateKey`, and raw Bearer/JWT tokens before structured logging.

---

## 🚀 Quickstart

```ts
import { IdempotencyGuard, validateWebhookUrl, redactSensitiveFields } from "ts-idempotent-webhook-guard";

const guard = new IdempotencyGuard({ ttlMs: 300_000 });

const { result, replayed } = await guard.execute("payment-ref-2026-01", async () => {
  return { status: "credited", amountUsdc: 100 };
});
```

## 🧪 Running Tests

```bash
npm test
```

## 📄 License

Released under the [MIT License](LICENSE).
