import { Injectable, Inject, Optional } from '@nestjs/common';
import { Logger as PinoLogger } from 'nestjs-pino';
import { ClsService } from 'nestjs-cls';

/**
 * UicpLogger — Pino child logger factory that auto-injects CLS context.
 *
 * Every log line emitted through this service automatically includes:
 *   - requestId, traceId, tenantId, userId, sessionId  (from CLS store)
 *
 * Error logs additionally carry:
 *   - errorCode, errorCategory, httpStatus, ipHash, threatScore
 *
 * Implements: Req 1 (audit trail), Req 13.6
 */
@Injectable()
export class UicpLogger {
  constructor(
    private readonly pino: PinoLogger,
    @Optional() private readonly cls: ClsService | undefined,
  ) {}

  /** Build the CLS context object to merge into every log line. */
  private clsContext(): Record<string, unknown> {
    if (!this.cls) return {};
    return {
      requestId: this.cls.get('requestId'),
      traceId: this.cls.get('traceId'),
      tenantId: this.cls.get('tenantId'),
      tenantType: this.cls.get('tenantType'),
      isolationTier: this.cls.get('isolationTier'),
      principalId: this.cls.get('principalId'),
      membershipId: this.cls.get('membershipId'),
      actorId: this.cls.get('actorId'),
      userId: this.cls.get('userId'),
      sessionId: this.cls.get('sessionId'),
      policyVersion: this.cls.get('policyVersion'),
      manifestVersion: this.cls.get('manifestVersion'),
    };
  }

  log(message: string, context?: string, extra?: Record<string, unknown>): void {
    this.pino.log({ ...this.clsContext(), ...extra }, message, context);
  }

  debug(message: string, context?: string, extra?: Record<string, unknown>): void {
    this.pino.debug({ ...this.clsContext(), ...extra }, message, context);
  }

  warn(message: string, context?: string, extra?: Record<string, unknown>): void {
    this.pino.warn({ ...this.clsContext(), ...extra }, message, context);
  }

  /**
   * Structured error log.
   * Always includes errorCode, errorCategory, httpStatus, ipHash, threatScore
   * when provided — never raw IP addresses.
   */
  error(
    message: string,
    context?: string,
    extra?: {
      err?: unknown;
      errorCode?: string;
      errorCategory?: string;
      httpStatus?: number;
      ipHash?: string;       // HMAC of IP — never raw IP
      threatScore?: number;
      [key: string]: unknown;
    },
  ): void {
    this.pino.error({ ...this.clsContext(), ...extra }, message, context);
  }
}
