import { Injectable, NestMiddleware, Inject, Optional } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import * as crypto from 'crypto';
import { IApiMetricsPort } from '../../../application/ports/driven/i-api-metrics.port';
import { INJECTION_TOKENS } from '../../../application/ports/injection-tokens';

// Path templates for common API patterns
const PATH_TEMPLATES: Array<{ pattern: RegExp; template: string }> = [
  { pattern: /^\/users\/[a-f0-9-]{36}$/, template: '/users/:id' },
  { pattern: /^\/sessions\/[a-f0-9-]{36}$/, template: '/sessions/:id' },
  { pattern: /^\/tenants\/[a-f0-9-]{36}$/, template: '/tenants/:id' },
  { pattern: /^\/roles\/[a-f0-9-]{36}$/, template: '/roles/:id' },
  { pattern: /^\/policies\/[a-f0-9-]{36}$/, template: '/policies/:id' },
];

function normalizePath(path: string): string {
  for (const { pattern, template } of PATH_TEMPLATES) {
    if (pattern.test(path)) {
      return template;
    }
  }
  return path;
}

function getIpHash(req: Request): string | undefined {
  const ip = req.ip || req.headers['x-forwarded-for'] as string || '';
  if (!ip) return undefined;
  return crypto.createHash('sha256').update(ip).digest('hex');
}

@Injectable()
export class ApiMetricsMiddleware implements NestMiddleware {
  constructor(
    @Optional() @Inject(INJECTION_TOKENS.API_METRICS_PORT)
    private readonly apiMetrics?: IApiMetricsPort,
  ) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const apiMetrics = this.apiMetrics;
    if (!apiMetrics) {
      next();
      return;
    }

    const startTime = Date.now();
    const pathTemplate = normalizePath(req.path);
    const tenantId = (req as any).tenantId || 'unknown';
    const userId = (req as any).userId;
    const principalId = (req as any).principalId;
    const correlationId = req.headers['x-correlation-id'] as string;

    // Capture response size
    const originalSend = res.send;
    let responseSize = 0;
    res.send = function (data: any): Response {
      responseSize = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(String(data));
      return originalSend.call(this, data);
    };

    res.on('finish', async () => {
      const latencyMs = Date.now() - startTime;
      const statusCode = res.statusCode;

      // Extract metrics from request if set by other components
      const dbQueryCount = (req as any)._dbQueryCount || 0;
      const dbQueryTimeMs = (req as any)._dbQueryTimeMs || 0;
      const cacheHit = (req as any)._cacheHit || false;
      const externalApiCalls = (req as any)._externalApiCalls || 0;
      const externalApiTimeMs = (req as any)._externalApiTimeMs || 0;

      await apiMetrics.record({
        tenantId,
        userId,
        principalId,
        method: req.method,
        path: req.path,
        pathTemplate,
        statusCode,
        latencyMs,
        dbQueryCount,
        dbQueryTimeMs,
        cacheHit,
        externalApiCalls,
        externalApiTimeMs,
        requestSizeBytes: parseInt(req.headers['content-length'] as string) || undefined,
        responseSizeBytes: responseSize || undefined,
        userAgent: req.headers['user-agent'],
        ipHash: getIpHash(req),
        correlationId,
        errorType: statusCode >= 500 ? 'server_error' : statusCode >= 400 ? 'client_error' : undefined,
      }).catch(() => {}); // Non-blocking
    });

    next();
  }
}