#!/usr/bin/env node
import * as fs from "node:fs";
import {
  computeHmacSha256Hex,
  deriveStellarAnchorIdempotencyKey,
  redactSensitiveFields,
  validateStellarAnchorWebhook,
  validateWebhookUrl,
  verifyHmacSha256Signature,
  verifyStripeSignatureHeader,
} from "../src/index.mjs";

const args = process.argv.slice(2);
const cmd = args[0];

if (!cmd) {
  console.error("Usage:");
  console.error("  webhook-guard --verify-payload <file.json> [--secret <hmac_secret>]");
  console.error("  webhook-guard --verify-sep24 <file.json> [--secret <hmac_secret>]");
  console.error("  webhook-guard validate-url <url>");
  console.error("  webhook-guard sign-hmac <secret> <payload> [timestamp]");
  console.error("  webhook-guard verify-hmac <secret> <payload> <signature>");
  console.error("  webhook-guard redact '<json>'");
  process.exit(1);
}

if (cmd === "--verify-payload" || cmd === "verify-payload" || cmd === "--verify-sep24" || cmd === "verify-sep24") {
  const filePath = args[1];
  if (!filePath) {
    console.error(JSON.stringify({ valid: false, reason: "Missing payload file argument" }, null, 2));
    process.exit(2);
  }

  let secret = null;
  if (args.includes("--secret")) {
    const sIdx = args.indexOf("--secret");
    if (sIdx + 1 < args.length) {
      secret = args[sIdx + 1];
    }
  }

  let rawContent;
  try {
    rawContent = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    console.error(JSON.stringify({ valid: false, reason: `Failed to read file: ${err.message}` }, null, 2));
    process.exit(2);
  }

  let parsed;
  try {
    parsed = JSON.parse(rawContent);
  } catch (err) {
    console.error(JSON.stringify({ valid: false, reason: `Invalid JSON syntax: ${err.message}` }, null, 2));
    process.exit(2);
  }

  const validation = validateStellarAnchorWebhook(parsed);
  if (!validation.valid) {
    console.log(JSON.stringify({ valid: false, reason: validation.reason }, null, 2));
    process.exit(2);
  }

  const idempotencyKey = deriveStellarAnchorIdempotencyKey(parsed);
  const tx = parsed.transaction ?? parsed;
  const out = {
    valid: true,
    idempotencyKey,
    transactionId: tx.id,
    status: tx.status,
  };
  if (secret) {
    out.signature = computeHmacSha256Hex(rawContent, secret);
  }
  console.log(JSON.stringify(out, null, 2));
  process.exit(0);
} else if (cmd === "validate-url") {
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
  try {
    const input = JSON.parse(args[1] || "{}");
    console.log(JSON.stringify(redactSensitiveFields(input), null, 2));
  } catch (err) {
    console.error(JSON.stringify({ error: "Invalid JSON payload", detail: String(err?.message || err) }));
    process.exit(2);
  }
} else {
  console.error(`Unknown command: ${cmd}`);
  process.exit(1);
}
