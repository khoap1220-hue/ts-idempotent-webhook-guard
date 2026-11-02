export declare class FileWalIdempotencyStore {
  readonly filePath: string;
  constructor(filePath: string);
  loadActiveEntries(now?: number): Map<string, { value: any; expiresAt: number }>;
  appendEntry(key: string, entry: { value: any; expiresAt: number }): void;
  compact(now?: number): number;
  compactWal(options?: { maxAgeMs?: number }): CompactWalResult;
}

export interface IdempotencyOptions {
  ttlMs?: number;
  maxEntries?: number;
  store?: FileWalIdempotencyStore;
}

export interface IdempotencyExecutionResult<T> {
  result: T;
  replayed: boolean;
}

export declare class IdempotencyGuard {
  constructor(options?: IdempotencyOptions);
  has(key: string): boolean;
  execute<T>(key: string, handler: () => Promise<T>): Promise<IdempotencyExecutionResult<T>>;
  compactWal(options?: { maxAgeMs?: number }): CompactWalResult;
}

export declare function verifyTimingSafeToken(
  providedHeaderOrToken: string | undefined | null,
  expectedSecret: string | undefined | null
): boolean;

export declare function computeHmacSha256Hex(rawBody: string | Buffer, secret: string): string;

export declare function verifyHmacSha256Signature(
  rawBody: string | Buffer,
  signatureHeader: string | undefined | null,
  secret: string
): boolean;

export interface StripeVerificationResult {
  valid: boolean;
  reason?: string;
  timestamp?: number;
}

export declare function verifyStripeSignatureHeader(
  rawBody: string | Buffer,
  stripeHeader: string | undefined | null,
  secret: string,
  options?: { toleranceSeconds?: number; nowSeconds?: number }
): StripeVerificationResult;

export interface WebhookValidationResult {
  valid: boolean;
  reason?: string;
  normalizedUrl?: string;
}

export declare function validateWebhookUrl(
  rawUrl: string,
  options?: { allowLocalhostHttps?: boolean }
): WebhookValidationResult;

export declare function redactSensitiveFields<T>(payload: T): T;

export interface CompactWalResult {
  beforeLines: number;
  afterLines: number;
  bytesReclaimed: number;
}

export declare const IdempotentWebhookGuard: typeof IdempotencyGuard;
