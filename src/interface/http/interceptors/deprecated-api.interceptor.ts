import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';
import { MetricsService } from '../../../../src/application/services/platform-ops/metrics.service';

@Injectable()
export class DeprecatedApiInterceptor implements NestInterceptor {
  private readonly logger = new Logger(DeprecatedApiInterceptor.name);

  constructor(private readonly metrics: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();

    // Inject standard deprecation headers
    res.setHeader('Deprecation', 'true');
    res.setHeader('Sunset', '2026-08-01T00:00:00Z');
    res.setHeader('Link', '<https://docs.uicp.com/migration>; rel="deprecation"');
    res.setHeader('Warning', '299 - "This API is deprecated and will be removed. Migrate to /v1/users/me/*"');

    return next.handle().pipe(
      tap(() => {
        const route = req.path;
        const clientId = req.headers['x-client-id'] || 'unknown';
        const userId = (req as any).user?.sub || 'unauthenticated';

        // 1. Log telemetry for migration tracking
        this.logger.warn({
          event: 'DEPRECATED_API_USAGE',
          route,
          clientId,
          userId,
          ip: req.ip,
          ts: Date.now()
        });

        // 2. Export Prometheus Metric
        // Assuming we add a counter for deprecated API usage
        if (this.metrics['deprecatedApiTotal']) {
           this.metrics['deprecatedApiTotal'].inc({ route, client_id: clientId as string });
        }
      })
    );
  }
}
