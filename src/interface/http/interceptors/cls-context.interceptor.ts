import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { ClsService } from 'nestjs-cls';

/**
 * ClsContextInterceptor — populates the CLS store for the entire async call stack.
 *
 * Implements: Req 3.8
 *
 * Reads request identity and runtime context from the request and makes it
 * available across the async call stack.
 * request object (populated by guards and middleware) and stores them in
 * AsyncLocalStorage via nestjs-cls so every downstream service can access
 * them without explicit parameter threading.
 */
@Injectable()
export class ClsContextInterceptor implements NestInterceptor {
  constructor(private readonly cls: ClsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Record<string, unknown> & { headers: Record<string, string | string[] | undefined> }>();

    const requestId =
      (req['id'] as string | undefined) ??
      (req.headers['x-request-id'] as string | undefined) ??
      crypto.randomUUID();

    const traceId =
      (req.headers['x-trace-id'] as string | undefined) ??
      (req.headers['traceparent'] as string | undefined) ??
      requestId;

    this.cls.set('requestId', requestId);
    this.cls.set('tenantId', req['tenantId'] as string | undefined);
    this.cls.set('tenantType', req['tenantType'] as string | undefined);
    this.cls.set('isolationTier', req['isolationTier'] as string | undefined);
    this.cls.set('principalId', req['principalId'] as string | undefined);
    this.cls.set('membershipId', req['membershipId'] as string | undefined);
    this.cls.set('actorId', req['actorId'] as string | undefined);
    this.cls.set('userId', req['userId'] as string | undefined);
    this.cls.set('traceId', traceId);
    this.cls.set('sessionId', req['sessionId'] as string | undefined);
    this.cls.set('policyVersion', req['policyVersion'] as string | undefined);
    this.cls.set('manifestVersion', req['manifestVersion'] as string | undefined);

    return next.handle();
  }
}
