import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { map, Observable } from 'rxjs';
import { ClsService } from 'nestjs-cls';

export interface ResponseEnvelope<T = unknown> {
  data: T;
  meta: {
    requestId: string;
    timestamp: string;
  };
}

/**
 * ResponseEnvelopeInterceptor — wraps all successful responses in a standard envelope.
 *
 * Implements: Req 1.6
 *
 * Output shape:
 * ```json
 * {
 *   "data": <original response>,
 *   "meta": { "requestId": "...", "timestamp": "..." }
 * }
 * ```
 *
 * Responses that are already enveloped (have a `data` key at the top level)
 * are passed through as-is to avoid double-wrapping.
 */
@Injectable()
export class ResponseEnvelopeInterceptor implements NestInterceptor {
  constructor(private readonly cls: ClsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<ResponseEnvelope> {
    const req = context.switchToHttp().getRequest<Record<string, unknown>>();

    return next.handle().pipe(
      map((body) => {
        // Avoid double-wrapping if handler already returned an envelope
        if (body !== null && typeof body === 'object' && 'data' in (body as object) && 'meta' in (body as object)) {
          return body as ResponseEnvelope;
        }

        const requestId =
          (this.cls.get('requestId') as string | undefined) ??
          (req['id'] as string | undefined) ??
          '';

        return {
          data: body,
          meta: {
            requestId,
            timestamp: new Date().toISOString(),
          },
        };
      }),
    );
  }
}
