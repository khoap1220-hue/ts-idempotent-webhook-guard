# Roadmap — `ts-idempotent-webhook-guard`

- [x] Concurrent `Promise.all` in-flight execution lock (`IdempotencyGuard`).
- [x] Crash-safe JSONL Write-Ahead Log persistence (`FileWalIdempotencyStore`).
- [x] Constant-time HMAC-SHA256 & Stripe replay-window (`t=...,v1=...`) signature verifier.
- [x] IPv4/IPv6 loopback, link-local, and RFC 1918 SSRF target URL validator.
- [ ] Optional Stellar SEP-24 interactive anchor callback signature helper.
