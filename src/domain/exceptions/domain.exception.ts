import { HttpStatus } from '@nestjs/common';
import { type DomainErrorCode } from './domain-error-codes';

/**
 * Maps DomainErrorCode to HTTP status codes.
 * Ensures error responses are semantically correct (e.g., NOT_FOUND -> 404, CONFLICT -> 409).
 */
function errorCodeToHttpStatus(code: DomainErrorCode): number {
  switch (code) {
    // 404 — resource not found
    case 'USER_NOT_FOUND':
    case 'IDENTITY_NOT_FOUND':
    case 'INVALID_SESSION_ID':
    case 'INVALID_TOKEN_ID':
    case 'TOKEN_NOT_FOUND':
    case 'SESSION_NOT_FOUND':
      return HttpStatus.NOT_FOUND;

    // 409 — conflict
    case 'IDENTITY_ALREADY_EXISTS':
    case 'IDENTITY_ALREADY_LINKED':
    case 'IDENTITY_ALREADY_VERIFIED':
    case 'SESSION_ALREADY_TERMINATED':
    case 'REFRESH_TOKEN_REUSE':
    case 'OTP_ALREADY_USED':
      return HttpStatus.CONFLICT;

    // 400 — bad request / invalid input
    case 'INVALID_EMAIL':
    case 'DISPOSABLE_EMAIL_DOMAIN':
    case 'INVALID_PHONE_NUMBER':
    case 'WEAK_PASSWORD':
    case 'COMMON_PASSWORD':
    case 'INVALID_TENANT_ID':
    case 'INVALID_USER_ID':
    case 'INVALID_IDENTITY_ID':
    case 'INVALID_CREDENTIALS':
    case 'INVALID_OAUTH_STATE':
    case 'INVALID_ABAC_CONDITION':
    case 'INVALID_OTP':
      return HttpStatus.BAD_REQUEST;

    // 422 — business rule violation (default for domain errors)
    case 'CANNOT_ACTIVATE_WITHOUT_VERIFIED_IDENTITY':
    case 'INVALID_STATUS_TRANSITION':
    case 'MAX_IDENTITIES_PER_TYPE_EXCEEDED':
    case 'INVALID_SESSION_TRANSITION':
      return HttpStatus.UNPROCESSABLE_ENTITY;

    // 403 — forbidden / access denied
    case 'ACCOUNT_DELETED':
    case 'ACCOUNT_SUSPENDED':
    case 'ACCOUNT_NOT_ACTIVATED':
    case 'FORBIDDEN':
    case 'CROSS_TENANT_ACCESS_DENIED':
      return HttpStatus.FORBIDDEN;

    // 410 — gone (resource permanently unavailable)
    case 'TOKEN_REVOKED':
      return 410;

    // 429 — rate limiting / throttling
    case 'RATE_LIMIT_EXCEEDED':
      return HttpStatus.TOO_MANY_REQUESTS;

    // 503 — external service unavailable
    case 'CIRCUIT_BREAKER_OPEN':
      return HttpStatus.SERVICE_UNAVAILABLE;

    // 422 — OTP-specific business rules
    case 'OTP_EXPIRED':
    case 'NO_PROVIDER_CONFIGURED':
    case 'WIDGET_NOT_CONFIGURED':
    case 'RISK_THRESHOLD_EXCEEDED':
    case 'VERIFY_BLOCKED':
    case 'TENANT_NOT_FOUND':
    case 'TENANT_ISOLATION_VIOLATION':
      return HttpStatus.UNPROCESSABLE_ENTITY;

    default:
      return HttpStatus.UNPROCESSABLE_ENTITY;
  }
}

export class DomainException extends Error {
  constructor(
    public readonly errorCode: DomainErrorCode,
    message?: string,
  ) {
    super(message ?? errorCode);
    this.name = 'DomainException';
    // Maintain proper prototype chain in transpiled ES5
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Maps the domain error code to an appropriate HTTP status.
   */
  toHttpStatus(): number {
    return errorCodeToHttpStatus(this.errorCode);
  }
}

export class IntegrityViolationException extends Error {
  constructor(public readonly alertId: string) {
    super(`Integrity violation detected for alert: ${alertId}`);
    this.name = 'IntegrityViolationException';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
