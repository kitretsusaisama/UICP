import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Inject,
  Optional,
} from '@nestjs/common';
import { DomainException } from '../../../domain/exceptions/domain.exception';
import { AuthenticationException } from '../../../domain/exceptions/authentication.exception';
import { SchemaValidationException } from '../../../domain/exceptions/schema-validation.exception';
import { InfrastructureException } from '../../../domain/exceptions/infrastructure.exception';
import { IMetricsPort } from '../../../application/ports/driven/i-metrics.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';
import { ClsService } from 'nestjs-cls';
import { UicpLogger } from '../../../shared/logger/pino-logger.service';

/**
 * GlobalExceptionFilter — maps all exceptions to structured HTTP error responses.
 *
 * Implements: Req 1.6, Req 3.8
 *
 * Exception → HTTP status mapping:
 *  - DomainException          → 422 Unprocessable Entity
 *  - AuthenticationException  → 401 Unauthorized
 *  - SchemaValidationException → 400 Bad Request
 *  - ConflictException (NestJS) → 409 Conflict
 *  - InfrastructureException  → 503 Service Unavailable
 *  - HttpException            → status from exception
 *  - Unknown                  → 500 Internal Server Error
 *
 * Every error emits:
 *  - Pino structured log with requestId, tenantId, errorCode
 *  - Prometheus counter `uicp_http_errors_total` with labels
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  constructor(
    @Optional() @Inject(INJECTION_TOKENS.METRICS_PORT)
    private readonly metrics: IMetricsPort | undefined,
    @Optional()
    private readonly cls: ClsService | undefined,
    @Optional()
    private readonly logger: UicpLogger | undefined,
  ) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<{ status(code: number): { json(body: unknown): void }; setHeader(key: string, value: string): void }>();
    const req = ctx.getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();

    const { status, errorCode, message, details, retryAfter } = this.classify(exception);

    const requestId =
      (this.cls?.get('requestId') as string | undefined) ??
      (req['id'] as string | undefined) ??
      '';

    const tenantId =
      (this.cls?.get('tenantId') as string | undefined) ??
      (req['tenantId'] as string | undefined);

    const correlationId =
      (req.headers?.['x-correlation-id'] as string | undefined) ??
      requestId;

    // Determine error category from exception type
    const errorCategory = this.categorize(exception);

    // ipHash from request (never raw IP)
    const ipHash = req['ipHash'] as string | undefined;

    // threatScore if available (e.g. from UEBA context)
    const threatScore = req['threatScore'] as number | undefined;

    const logExtra = {
      errorCode,
      errorCategory,
      httpStatus: status,
      ...(ipHash ? { ipHash } : {}),
      ...(threatScore !== undefined ? { threatScore } : {}),
      err: status >= 500 ? exception : undefined,
    };

    if (this.logger) {
      if (status >= 500) {
        this.logger.error(message, GlobalExceptionFilter.name, logExtra);
      } else if (status >= 400) {
        this.logger.warn(message, GlobalExceptionFilter.name, { ...logExtra, err: undefined });
      }
    }

    // Prometheus counter
    this.metrics?.increment('uicp_http_errors_total', {
      status: String(status),
      error_code: errorCode,
    });

    // Add error tracking headers
    const errorId = `err_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    res.setHeader('X-Correlation-ID', correlationId);
    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Error-ID', errorId);

    // Add rate limit headers when applicable
    if (status === 429) {
      res.setHeader('X-RateLimit-Limit', '1000');
      res.setHeader('X-RateLimit-Remaining', '0');
      res.setHeader('X-RateLimit-Reset', String(Math.floor(Date.now() / 1000) + 60));
      res.setHeader('Retry-After', '60');
    }

    res.status(status).json({
      success: false,
      error: {
        code: errorCode,
        message,
        ...(details ? { details } : {}),
        retryable: status === 429 || status === 503,
      },
      meta: {
        requestId,
        timestamp: new Date().toISOString(),
        version: 'v1',
      },
    });
  }

  private categorize(exception: unknown): string {
    if (exception instanceof DomainException) return 'DOMAIN';
    if (exception instanceof AuthenticationException) return 'AUTHENTICATION';
    if (exception instanceof SchemaValidationException) return 'VALIDATION';
    if (exception instanceof InfrastructureException) return 'INFRASTRUCTURE';
    if (exception instanceof HttpException) return 'HTTP';
    return 'UNKNOWN';
  }

  private classify(exception: unknown): {
    status: number;
    errorCode: string;
    message: string;
    details?: unknown;
    retryAfter?: number;
  } {
    // Domain business rule violations
    if (exception instanceof DomainException) {
      return {
        status: exception.toHttpStatus(),
        errorCode: exception.errorCode,
        message: exception.message,
      };
    }

    // Authentication failures
    if (exception instanceof AuthenticationException) {
      return {
        status: HttpStatus.UNAUTHORIZED,
        errorCode: exception.errorCode,
        message: exception.message,
      };
    }

    // Schema / input validation failures
    if (exception instanceof SchemaValidationException) {
      return {
        status: exception.httpStatus,
        errorCode: 'validation_error',
        message: exception.message,
        details: exception.errors,
      };
    }

    // Infrastructure / dependency failures
    if (exception instanceof InfrastructureException) {
      return {
        status: HttpStatus.SERVICE_UNAVAILABLE,
        errorCode: exception.errorCode,
        message: exception.message,
      };
    }

    // Rate limit exceeded
    if (exception instanceof HttpException && exception.getStatus() === 429) {
      return {
        status: HttpStatus.TOO_MANY_REQUESTS,
        errorCode: 'RATE_LIMIT_EXCEEDED',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: 60,
      };
    }

    // NestJS built-in HTTP exceptions (includes ConflictException, BadRequestException, etc.)
    if (exception instanceof HttpException) {
      const response = exception.getResponse();
      const status = exception.getStatus();

      if (typeof response === 'object' && response !== null && 'error' in response) {
        const r = response as { error: { code?: string; message?: string } };
        return {
          status,
          errorCode: r.error.code ?? this.statusToCode(status),
          message: r.error.message ?? exception.message,
        };
      }

      return {
        status,
        errorCode: this.statusToCode(status),
        message: typeof response === 'string' ? response : exception.message,
      };
    }

    // Unknown / unhandled errors
    return {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      errorCode: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
    };
  }

  private statusToCode(status: number): string {
    const map: Record<number, string> = {
      400: 'BAD_REQUEST',
      401: 'UNAUTHORIZED',
      403: 'FORBIDDEN',
      404: 'NOT_FOUND',
      409: 'CONFLICT',
      422: 'UNPROCESSABLE_ENTITY',
      429: 'TOO_MANY_REQUESTS',
      500: 'INTERNAL_SERVER_ERROR',
      503: 'SERVICE_UNAVAILABLE',
    };
    return map[status] ?? 'HTTP_ERROR';
  }
}
