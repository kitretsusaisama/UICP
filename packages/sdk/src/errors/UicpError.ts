/**
 * @uicp/sdk - Error Hierarchy
 *
 * Structured error types with rich context for debugging and handling
 */

import { RateLimitTier } from '../types';

/** Base error for all UICP errors */
export class UicpError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly traceId?: string;
  public readonly tenantId?: string;
  public readonly raw?: unknown;

  constructor(
    code: string,
    message: string,
    statusCode: number,
    options?: {
      traceId?: string;
      tenantId?: string;
      raw?: unknown;
    },
  ) {
    super(message);
    this.name = 'UicpError';
    this.code = code;
    this.statusCode = statusCode;
    this.traceId = options?.traceId;
    this.tenantId = options?.tenantId;
    this.raw = options?.raw;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UicpError);
    }
  }

  isRetryable(): boolean {
    return this.statusCode === 429 || this.statusCode === 0;
  }

  toJSON(): object {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
      traceId: this.traceId,
      tenantId: this.tenantId,
    };
  }
}

export class UicpRateLimitError extends UicpError {
  public readonly rateLimitTier: RateLimitTier;
  public readonly retryAfterMs?: number;

  constructor(
    message: string,
    rateLimitTier: RateLimitTier,
    options?: { retryAfterMs?: number; traceId?: string },
  ) {
    super('RATE_LIMIT_EXCEEDED', message, 429, { traceId: options?.traceId });
    this.name = 'UicpRateLimitError';
    this.rateLimitTier = rateLimitTier;
    this.retryAfterMs = options?.retryAfterMs;
  }

  getRetryDelay(): number {
    return this.retryAfterMs ?? 1000;
  }
}

export class UicpSessionExpiredError extends UicpError {
  constructor(options?: { traceId?: string; tenantId?: string }) {
    super('TOKEN_REUSE_DETECTED', 'Session expired due to token reuse', 401, {
      traceId: options?.traceId,
      tenantId: options?.tenantId,
    });
    this.name = 'UicpSessionExpiredError';
  }
}

export class UicpNotImplementedError extends UicpError {
  public readonly apiName: string;

  constructor(apiName: string, reason: string) {
    super('NOT_IMPLEMENTED', `${apiName}: ${reason}`, 501);
    this.name = 'UicpNotImplementedError';
    this.apiName = apiName;
  }
}

export class UicpNetworkError extends UicpError {
  public readonly cause: unknown;

  constructor(cause: unknown, options?: { traceId?: string }) {
    super('NETWORK_ERROR', 'Network request failed', 0, { traceId: options?.traceId, raw: cause });
    this.name = 'UicpNetworkError';
    this.cause = cause;
  }

  override isRetryable(): boolean {
    return true;
  }
}

export class UicpValidationError extends UicpError {
  public readonly validationErrors: Record<string, string[]>;

  constructor(validationErrors: Record<string, string[]>, message = 'Validation failed') {
    super('VALIDATION_ERROR', message, 400);
    this.name = 'UicpValidationError';
    this.validationErrors = validationErrors;
  }
}

export class UicpAuthenticationError extends UicpError {
  constructor(message = 'Authentication failed', options?: { traceId?: string }) {
    super('AUTHENTICATION_FAILED', message, 401, { traceId: options?.traceId });
    this.name = 'UicpAuthenticationError';
  }
}

export class UicpAuthorizationError extends UicpError {
  constructor(message = 'Authorization failed', options?: { traceId?: string }) {
    super('AUTHORIZATION_FAILED', message, 403, { traceId: options?.traceId });
    this.name = 'UicpAuthorizationError';
  }
}

export function isUicpError(err: unknown): err is UicpError {
  return err instanceof UicpError;
}

export function isRateLimitError(err: unknown): err is UicpRateLimitError {
  return err instanceof UicpRateLimitError;
}

export function isSessionExpiredError(err: unknown): err is UicpSessionExpiredError {
  return err instanceof UicpSessionExpiredError;
}

export function isNetworkError(err: unknown): err is UicpNetworkError {
  return err instanceof UicpNetworkError;
}

export function createErrorFromResponse(
  statusCode: number,
  data: unknown,
  headers: Record<string, string>,
): UicpError {
  const traceId = headers['x-request-id'] ?? headers['x-trace-id'];
  const message = typeof data === 'object' && data !== null
    ? (data as Record<string, unknown>)['message'] as string ?? 'Unknown error'
    : 'Unknown error';

  const errorCode = typeof data === 'object' && data !== null
    ? (data as Record<string, unknown>)['code'] as string ?? 'UNKNOWN'
    : 'UNKNOWN';

  if (statusCode === 429) {
    const retryAfter = parseInt(headers['retry-after'] ?? '1000', 10);
    const tierHeader = headers['x-rate-limit-tier'] as string;
    const tier = tierHeader && Object.values(RateLimitTier).includes(tierHeader as RateLimitTier) ? tierHeader as RateLimitTier : RateLimitTier.LOGIN;
    return new UicpRateLimitError(message, tier, { retryAfterMs: retryAfter * 1000, traceId });
  }

  if (statusCode === 401 && errorCode === 'TOKEN_REUSE_DETECTED') {
    return new UicpSessionExpiredError({ traceId });
  }

  return new UicpError(errorCode, message, statusCode, { traceId, raw: data });
}