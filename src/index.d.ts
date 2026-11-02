export interface IdempotencyOptions {
  ttlMs?: number;
}

export interface IdempotencyExecutionResult<T> {
  result: T;
  replayed: boolean;
}

export declare class IdempotencyGuard {
  constructor(options?: IdempotencyOptions);
  execute<T>(key: string, handler: () => Promise<T>): Promise<IdempotencyExecutionResult<T>>;
}

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
