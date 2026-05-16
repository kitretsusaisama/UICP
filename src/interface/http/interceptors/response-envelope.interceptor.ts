import { CallHandler, ExecutionContext, Injectable, NestInterceptor, Logger } from '@nestjs/common';
import { map, Observable } from 'rxjs';
import { ClsService } from 'nestjs-cls';
import * as crypto from 'crypto';

export interface ResponseEnvelope<T = unknown> {
  data: T;
  meta: {
    requestId: string;
    correlationId: string;
    timestamp: string;
    version: string;
    responseTime?: number;
  };
  links?: Record<string, string>;
}

export interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    details?: Array<{ field: string; message: string; code: string }>;
    correlationId: string;
  };
  meta: { requestId: string; timestamp: string };
}

/**
 * ResponseEnvelopeInterceptor — Enterprise-grade response wrapper
 *
 * Features:
 * - Standardizes responses with { data, meta, links }
 * - Injects correlation ID for tracing
 * - Tracks response time
 * - Supports pagination links
 */
@Injectable()
export class ResponseEnvelopeInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ResponseEnvelopeInterceptor.name);
  private readonly startTime: Map<string, number> = new Map();

  constructor(private readonly cls: ClsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<ResponseEnvelope> {
    const req = context.switchToHttp().getRequest<Record<string, unknown>>();
    const res = context.switchToHttp().getResponse();

    const correlationId = this.getOrCreateCorrelationId(req);
    const requestId = this.generateRequestId();

    this.startTime.set(correlationId, Date.now());
    res.setHeader('X-Correlation-ID', correlationId);
    res.setHeader('X-Request-ID', requestId);

    return next.handle().pipe(
      map((body) => {
        const responseTime = this.calculateResponseTime(correlationId);
        const meta = { requestId, correlationId, timestamp: new Date().toISOString(), version: 'v1', responseTime };

        let dataPayload = body;
        if (body !== null && typeof body === 'object' && 'data' in (body as object)) {
          dataPayload = (body as Record<string, unknown>).data;
        }

        let links: Record<string, string> | undefined;
        if (body !== null && typeof body === 'object' && 'links' in (body as object)) {
          links = (body as Record<string, unknown>).links as Record<string, string>;
        }

        return { data: dataPayload ?? null, meta, ...(links && { links }) };
      }),
    );
  }

  private getOrCreateCorrelationId(req: Record<string, unknown>): string {
    const headers = req['headers'] as Record<string, string> | undefined;
    return headers?.['x-correlation-id'] || headers?.['x-request-id'] || `corr_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  private generateRequestId(): string { return `req_${crypto.randomBytes(12).toString('hex')}`; }

  private calculateResponseTime(correlationId: string): number {
    const start = this.startTime.get(correlationId);
    if (start) { this.startTime.delete(correlationId); return Date.now() - start; }
    return 0;
  }
}
