import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { map, Observable } from 'rxjs';
import { ClsService } from 'nestjs-cls';

export interface ResponseEnvelope<T = unknown> {
  success: boolean;
  data: T;
  meta: {
    requestId: string;
    timestamp: string;
    version: string;
  };
}

/**
 * ResponseEnvelopeInterceptor — wraps all successful responses in a standard MNC-grade envelope.
 *
 * Implements: MNC-Grade Execution Plan (Phase 1)
 *
 * Output shape:
 * ```json
 * {
 *   "success": true,
 *   "data": <original response>,
 *   "meta": { "requestId": "...", "timestamp": "...", "version": "v1" }
 * }
 * ```
 *
 * Handlers that return `{ data: ... }` will be repacked correctly into the global shape.
 */
@Injectable()
export class ResponseEnvelopeInterceptor implements NestInterceptor {
  constructor(private readonly cls: ClsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<ResponseEnvelope> {
    const req = context.switchToHttp().getRequest<Record<string, unknown>>();

    return next.handle().pipe(
      map((body) => {
        const requestId =
          (this.cls.get('requestId') as string | undefined) ??
          (req['id'] as string | undefined) ??
          '';

        const meta = {
          requestId,
          timestamp: new Date().toISOString(),
          version: 'v1',
        };

        // Extract the data payload securely
        let dataPayload = body;
        if (body !== null && typeof body === 'object' && 'data' in (body as object)) {
          dataPayload = (body as Record<string, unknown>).data;
        }

        return {
          success: true,
          data: dataPayload ?? {},
          meta,
        };
      }),
    );
  }
}
