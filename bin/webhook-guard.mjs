#!/usr/bin/env node
import {
  computeHmacSha256Hex,
  redactSensitiveFields,
  validateWebhookUrl,
  verifyHmacSha256Signature,
  verifyStripeSignatureHeader,
} from "../src/index.mjs";

const args = process.argv.slice(2);
const cmd = args[0];

if (!cmd) {
  console.error("Usage:");
  console.error("  webhook-guard validate-url <url>");
  console.error("  webhook-guard sign-hmac <secret> <payload> [timestamp]");
  console.error("  webhook-guard verify-hmac <secret> <payload> <signature>");
  console.error("  webhook-guard redact '<json>'");
  process.exit(1);
}

if (cmd === "validate-url") {
  const res = validateWebhookUrl(args[1] || "");
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.valid ? 0 : 2);
} else if (cmd === "sign-hmac") {
  const secret = args[1] || "";
  const payload = args[2] || "";
  const ts = args[3];
  if (ts) {
    const v1 = computeHmacSha256Hex(`${ts}.${payload}`, secret);
    console.log(JSON.stringify({ stripeHeader: `t=${ts},v1=${v1}` }, null, 2));
  } else {
    const sig = computeHmacSha256Hex(payload, secret);
    console.log(JSON.stringify({ signatureHeader: `sha256=${sig}` }, null, 2));
  }
} else if (cmd === "verify-hmac") {
  const secret = args[1] || "";
  const payload = args[2] || "";
  const sig = args[3] || "";
  const valid = sig.includes("t=")
    ? verifyStripeSignatureHeader(payload, sig, secret).valid
    : verifyHmacSha256Signature(payload, sig, secret);
  console.log(JSON.stringify({ valid }, null, 2));
  process.exit(valid ? 0 : 2);
} else if (cmd === "redact") {
  const input = JSON.parse(args[1] || "{}");
  console.log(JSON.stringify(redactSensitiveFields(input), null, 2));
} else {
  console.error(`Unknown command: ${cmd}`);
  process.exit(1);
}
